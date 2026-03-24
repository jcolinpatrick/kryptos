# Interpretation Guide for Forensic Photo Analysis

## Table of Contents

1. [Metadata Analysis](#metadata-analysis)
2. [Statistical Analysis](#statistical-analysis)
3. [Channel Separation](#channel-separation)
4. [LSB Extraction](#lsb-extraction)
5. [Bit Plane Decomposition](#bit-plane-decomposition)
6. [Error Level Analysis](#error-level-analysis)
7. [Frequency Domain (FFT)](#frequency-domain-fft)
8. [Chi-Square Steganalysis](#chi-square-steganalysis)
9. [Edge and Contour Analysis](#edge-and-contour-analysis)
10. [OCR Results](#ocr-results)
11. [Kryptos-Specific Considerations](#kryptos-specific-considerations)

---

## Metadata Analysis

### What to look for

- **Software tags**: If the image has been processed through editing software (Photoshop,
  GIMP, etc.), this appears in the `Software` or `ProcessingSoftware` EXIF tags. For Kryptos
  photos, this helps establish provenance — was this a straight-from-camera capture or has
  someone post-processed it?

- **GPS coordinates**: Photos taken at the CIA HQ courtyard should have GPS data near
  38.9517°N, 77.1467°W. Discrepancies could indicate the image was geotagged incorrectly
  or is from a different location.

- **Thumbnail mismatch**: JPEG files contain an embedded thumbnail. If the main image was
  modified after capture but the thumbnail wasn't regenerated, the thumbnail shows the
  original pre-edit state. This is a classic forensic tell.

- **Custom/private tags**: EXIF supports manufacturer-specific and private tag ranges.
  Any unusual private tags could carry embedded data — report their raw hex content.

- **Camera identification**: The camera model and serial number establish which physical
  device captured the image, useful for authenticating provenance.

### False positives

- Social media platforms (Instagram, Twitter) strip most EXIF data on upload. Absence of
  metadata does not indicate tampering — it likely indicates the image passed through a
  platform.
- Smartphone cameras aggressively auto-process images (HDR, noise reduction, sharpening).
  A `Software` tag showing the phone's camera app is normal.

---

## Statistical Analysis

### What to look for

- **Entropy per channel**: Natural images typically have entropy between 6.0-7.5 bits/byte
  per channel. Values above 7.5 suggest the channel may contain embedded random data
  (steganographic payload). Values below 4.0 suggest highly uniform or synthetic content.

- **Histogram shape**: Natural photos produce smooth, often roughly normal distributions.
  Look for:
  - Comb-tooth patterns (alternating high/low bins): classic LSB embedding artifact
  - Bimodal distributions: possible compositing of two different exposure regions
  - Clipped ends (spikes at 0 or 255): over/underexposure or aggressive tone mapping
  - Unusual gaps or plateaus: quantization artifacts from format conversion

- **Skewness**: High positive skew = mostly dark image with bright outliers. High negative
  skew = mostly bright with dark outliers. Extreme skew (|skew| > 2) in any channel is
  unusual and warrants investigation.

- **Kurtosis**: High kurtosis means the distribution has heavy tails (extreme pixel values
  are more common than expected). This can indicate compositing or synthetic modification.

### Kryptos context

The copper panels of the Kryptos sculpture have a distinctive greenish patina. In photos,
expect the green channel to dominate and the blue channel to show moderate values. If the
red channel shows unexpectedly high entropy relative to the visual appearance, investigate
whether information is encoded in the red channel (which would be less visually obvious
against the green patina background).

---

## Channel Separation

### What to look for

- **Individual channel images**: View each channel (R, G, B, H, S, V) as a grayscale image.
  Information hidden in a single channel may be invisible in the composite image but
  apparent when that channel is viewed alone.

- **Difference maps (R-G, R-B, G-B)**: These highlight regions where color channels diverge.
  In a natural image, difference maps tend to be smooth and low-contrast. Sharp patterns or
  text visible in a difference map but not in the original image are highly suspicious.

- **HSV decomposition**: The Hue channel isolates color independently from brightness.
  The Saturation channel shows how vivid colors are. The Value channel is essentially
  brightness. Hidden information might exploit low-saturation regions (near-gray areas)
  where hue values become numerically unstable and can encode data without visible effect.

### Kryptos context

The sculpture's patina creates natural chromatic variation. Legitimate weathering patterns
will be visible across all channels. Look specifically for patterns that appear in only one
channel — Jim Sanborn is known for incorporating visual steganography, so information
encoded in the red channel against the green copper background would be both technically
feasible and artistically consistent.

---

## LSB Extraction

### What to look for

- **Bit plane visual patterns**: When the LSB (bit 0) plane is extracted and displayed as
  a black-and-white image, natural images produce a noise-like random pattern. If you see
  structure — text, shapes, regular patterns, or large uniform regions — this is evidence
  of intentional embedding.

- **ASCII extraction results**: The pipeline attempts to interpret LSB data as ASCII text
  (8 consecutive pixels → 1 byte). Long runs of printable characters (>8 bytes) are
  reported. Natural images occasionally produce short runs by chance, but runs longer than
  ~20 characters are statistically unlikely without intentional encoding.

- **Higher bit planes (bits 1-3)**: Some steganographic methods use more than just the LSB.
  Check bits 1, 2, and 3 for structure as well. The visual impact increases with higher
  bit planes (bit 3 modification is 8× more visible than bit 0).

### Interpreting entropy values

| LSB Entropy (bit 0) | Interpretation |
|---------------------|----------------|
| < 0.5               | Nearly all 0s or all 1s — extremely unusual, likely synthetic |
| 0.5 - 0.95          | Low entropy — possible structured data or simple encoding |
| 0.95 - 1.0          | High entropy — expected for natural images or encrypted payload |
| Exactly 1.0         | Perfect randomness — possible encrypted steganographic payload |

Note: Both natural images and encrypted steg payloads produce high entropy in the LSB
plane. The chi-square module provides a more discriminating test.

---

## Bit Plane Decomposition

### What to look for

Full decomposition produces 32 images (8 bits × 3 channels + 8 grayscale). Focus on:

- **Lower planes (0-2)**: Most steganographic methods embed in these planes because
  modification is least visible. Look for structure or patterns.

- **Upper planes (5-7)**: These carry the dominant visual information. Anomalies here
  affect the visible image and are harder to hide. However, some techniques embed
  data as a watermark across upper planes.

- **Cross-channel comparison**: If bit plane N of the red channel shows a pattern that
  doesn't appear in the same plane of green or blue, that's a strong indicator of
  single-channel embedding.

---

## Error Level Analysis

### What to look for

ELA is primarily useful for detecting **image manipulation** (compositing, copy-paste,
inpainting) rather than steganographic embedding.

- **Uniform ELA**: The entire image has roughly the same error level at each quality
  setting. This suggests the image has been saved once at a single JPEG quality or is
  a lossless original. This is the expected result for an unmodified photograph.

- **Localized hot spots**: A specific region shows dramatically higher error than the
  surrounding area. This indicates that region was added or modified after the initial
  compression — the modified pixels haven't been through the same number of JPEG
  compression cycles as the rest of the image.

- **Edge halos**: Bright edges in the ELA output are normal — JPEG compression artifacts
  concentrate at high-contrast boundaries. Don't confuse this with tampering.

### Limitations

- ELA only works on images that have been JPEG-compressed at least once. It produces
  no meaningful results on PNG, TIFF, or BMP originals.
- An image that has been saved many times at the same quality level will converge to
  uniform error regardless of tampering history. ELA is most effective on images that
  have been saved only 1-2 times.
- ELA cannot detect steganographic embedding that operates below the JPEG quantization
  noise floor.

---

## Frequency Domain (FFT)

### What to look for

- **Magnitude spectrum structure**: The DC component (center of the spectrum) represents
  the average brightness — it's always the brightest point. Natural images produce a
  spectrum that falls off roughly as 1/f from the center (this is a well-known property
  of natural scenes).

- **Discrete bright spots**: Points in the magnitude spectrum away from the center
  indicate periodic patterns in the spatial domain. A single bright point at position
  (u, v) means there is a sinusoidal pattern with that specific frequency and
  orientation in the image. Multiple bright spots in a regular arrangement indicate a
  grid-like hidden pattern.

- **Lines through the center**: A bright line in the frequency domain corresponds to
  edges at a specific angle in the spatial domain. This is normal for images with
  strong directional features (buildings, text lines, sculpture edges).

- **Phase spectrum**: Contains the spatial arrangement information. Phase is more
  important than magnitude for image structure. Unusual phase patterns can indicate
  watermarking techniques that modify phase rather than magnitude.

### Kryptos context

If the Kryptos sculpture encodes information as a physical grid pattern (e.g., a Cardan
grille with specific hole spacing), this pattern would appear as discrete frequency peaks
in the FFT. The peak positions directly encode the grid spacing: a peak at distance d
from center indicates a spatial period of N/d pixels (where N is the image dimension).

The directional band-pass outputs isolate horizontal and vertical frequency components.
If the sculpture text has a regular character spacing, this appears as a peak in the
horizontal band. Row spacing appears in the vertical band. Anomalous extra peaks beyond
the expected text grid may indicate an overlaid hidden pattern.

---

## Chi-Square Steganalysis

### What to look for

The chi-square test specifically detects **LSB replacement** steganography (the most
common technique, where the least significant bit of each pixel is replaced with
message bits).

- **Global p-value per channel**: A p-value below 0.05 indicates statistically significant
  evidence that the pixel value distribution has been modified in a way consistent with
  LSB replacement. Lower p-values = stronger evidence.

- **Spatial p-value map**: The block-wise heatmap shows where in the image LSB embedding
  is most likely. Red regions (low p-value) are probable embedding areas. Blue regions
  (high p-value) appear unmodified. This spatial information can reveal:
  - Whether the entire image or only a specific region was used for embedding
  - The approximate capacity utilization (what fraction of the image carries payload)
  - Whether the embedding follows a sequential, random, or structured pattern

### Limitations

- Only detects LSB *replacement* (overwriting the LSB). Does not detect LSB *matching*
  (incrementing or decrementing pixel values to match the desired bit) which is a more
  sophisticated technique.
- Requires sufficient pixel count per block for statistical significance. The test is
  unreliable on very small blocks or low-resolution images.
- JPEG compression artifacts can produce false positives, as quantization creates its own
  pair-distribution biases.

### Interpreting the p-value map

| P-value Range | Map Color | Interpretation |
|---------------|-----------|----------------|
| < 0.01        | Deep red  | Strong evidence of LSB embedding |
| 0.01 - 0.05   | Red/orange | Moderate evidence — investigate further |
| 0.05 - 0.20   | Yellow    | Weak evidence — possibly JPEG artifacts |
| 0.20 - 0.80   | Green     | No evidence — statistically normal |
| > 0.80        | Blue      | Very clean — no modification detected |

---

## Edge and Contour Analysis

### What to look for

- **Contour count and regularity**: A high contour count with regular spacing suggests
  a grid or structured pattern. This is relevant for detecting Cardan grille positioning
  or character grid alignment.

- **Shape metrics**: Circularity near 1.0 indicates circular features (holes, dots).
  Low circularity with consistent aspect ratios may indicate letter forms or symbols.

- **Grid regularity check**: If the centroids of detected contours fall on a regular grid
  (low coefficient of variation in spacing), this is reported as a finding. For Kryptos,
  the character layout on each panel should produce a detectable grid.

### Kryptos context

The Kryptos panels contain a grid of characters cut into copper sheeting. Edge detection
should reveal the character boundaries. Grid regularity analysis confirms the expected
character spacing. Any deviation from the regular grid — extra holes, displaced characters,
or secondary patterns overlaid on the primary text — could indicate encoding beyond the
visible cipher text.

---

## OCR Results

### What to look for

- **Primary text extraction**: The OCR module runs on multiple preprocessed variants of the
  image to maximize text recovery. The "best variant" (most characters extracted) is
  reported. For Kryptos panel photos, compare the extracted text against the known K1-K4
  cipher text to verify alignment.

- **Text in bit planes**: After running LSB/bitplane extraction, consider running OCR on
  the extracted bit plane images. Text visible in a bit plane but not in the original
  image is strong evidence of steganographic message embedding.

- **Confidence scores**: Low-confidence OCR results may indicate partially obscured or
  deliberately ambiguous characters — which on the Kryptos sculpture could be intentional
  misdirection or encoding.

---

## Kryptos-Specific Considerations

### Known steganographic elements

Jim Sanborn has confirmed that Kryptos contains layers of meaning beyond the four cipher
text passages. The sculpture includes physical features that may encode information:

- Morse code elements in the courtyard landscaping
- Compass rose and lodestone orientation
- The relationship between the sculpture panels and the reflecting pool
- Deliberate "misspellings" in the cipher text (e.g., K2's IQLUSION vs ILLUSION)

### Photographic analysis priorities for K4

When analyzing K4 photographs, prioritize in this order:

1. **Perspective correction** — Ensure the image is geometrically rectified before analysis
2. **Channel separation** — Look for single-channel hidden information against the patina
3. **FFT analysis** — Detect any periodic patterns (potential grille overlay)
4. **LSB/chi-square** — If the photo itself (not the sculpture) might carry embedded data
5. **Edge/contour analysis** — Verify character grid regularity, find anomalous features
6. **OCR** — Extract and validate the cipher text characters

### Photograph provenance

The analytical pipeline assumes the photograph itself is the object of analysis. However,
consider two distinct scenarios:

1. **Sculpture analysis** — The photo is a medium for examining the physical sculpture.
   Focus on perspective correction, OCR, edge detection, and visual pattern analysis.
   Steganographic modules (LSB, chi-square, ELA) are less relevant unless you suspect
   the photograph was intentionally modified to encode additional information.

2. **Photo analysis** — The digital photograph itself may have been modified to carry a
   steganographic payload. This is relevant if the photo source is a puzzle-maker or
   an entity known to embed digital steg. In this case, run the full pipeline including
   all steganographic modules.

Document which scenario applies and focus interpretation accordingly.
