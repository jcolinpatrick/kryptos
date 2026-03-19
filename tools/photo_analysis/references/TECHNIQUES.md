# Forensic Analysis Techniques — Theory and Background

## Table of Contents

1. [Steganography Fundamentals](#steganography-fundamentals)
2. [LSB Embedding and Detection](#lsb-embedding-and-detection)
3. [Chi-Square Attack Theory](#chi-square-attack-theory)
4. [Error Level Analysis Theory](#error-level-analysis-theory)
5. [Frequency Domain Techniques](#frequency-domain-techniques)
6. [Statistical Steganalysis](#statistical-steganalysis)
7. [Limitations and Edge Cases](#limitations-and-edge-cases)
8. [Academic References](#academic-references)

---

## Steganography Fundamentals

Steganography is the practice of concealing information within another medium such that
the existence of the hidden message is not apparent. Unlike cryptography (which makes
a message unreadable), steganography makes the message invisible.

In digital image steganography, the **cover image** is the original unmodified image,
the **stego image** is the image with embedded hidden data, and the **payload** is the
hidden data itself. The goal of steganalysis is to determine whether a given image is a
cover or stego image, and ideally to extract the payload.

### Embedding capacity

Theoretical maximum capacity of LSB embedding in an uncompressed image:

    capacity_bits = width × height × channels × bits_per_sample

For a 1920×1080 RGB image with 1-bit LSB embedding:
    = 1920 × 1080 × 3 × 1 = 6,220,800 bits ≈ 760 KB

In practice, embedding more than ~50% of capacity creates detectable statistical
artifacts. Most real-world steganographic tools limit embedding to 10-25% of capacity.

---

## LSB Embedding and Detection

### The technique

LSB replacement overwrites the least significant bit of each pixel value with one bit
of the message. For an 8-bit channel, this changes pixel values by at most ±1, which is
imperceptible to the human eye.

For pixel value P and message bit m:
    P_stego = (P & 0xFE) | m

This creates a characteristic artifact: in the original image, the counts of pixel
values 2k and 2k+1 are independent. After LSB embedding, these pairs are forced toward
equality because the LSB is determined by the message rather than the image content.

### Detection principle

The chi-square test exploits this pairing artifact. For each pair (2k, 2k+1), we test
whether their frequencies are significantly different from each other. Under the null
hypothesis (no embedding), these frequencies are independent. Under embedding, they
converge.

### LSB matching (±1 embedding)

A more sophisticated variant that avoids the pairing artifact: instead of replacing the
LSB, the pixel value is randomly incremented or decremented by 1 to match the desired
bit. This preserves the natural histogram shape and defeats the chi-square test.

Detection of LSB matching requires higher-order statistical tests (e.g., SPAM features,
SRM features) and is beyond the scope of the basic pipeline. The chi-square module will
report a negative result for LSB matching — this does NOT rule out steganography.

---

## Chi-Square Attack Theory

### Mathematical formulation

Given a histogram h[0..255] of pixel values in a region:

For each pair k = 0, 1, ..., 127:
    observed: (h[2k], h[2k+1])
    expected under embedding: ((h[2k] + h[2k+1])/2, (h[2k] + h[2k+1])/2)

Chi-square statistic:
    χ² = Σ_k [(h[2k] - e_k)² / e_k + (h[2k+1] - e_k)² / e_k]

where e_k = (h[2k] + h[2k+1]) / 2

Under H₀ (no embedding), χ² follows a chi-square distribution with 127 degrees
of freedom. A p-value below the significance threshold (typically 0.05) rejects H₀,
indicating embedding.

### Spatial localization

By computing the test on overlapping blocks rather than the whole image, we can
create a spatial map of embedding probability. This reveals whether:
- The entire image is embedded (sequential embedding)
- Only a specific region contains payload (selective embedding)
- The embedding follows a pattern (structured embedding)

### Sensitivity

The chi-square test requires sufficient pixel count per block. With 64×64 blocks
(4096 pixels), the test has good power for detecting embedding rates above ~25%.
For lower embedding rates, larger blocks are needed, which reduces spatial resolution.

---

## Error Level Analysis Theory

### Principle

JPEG compression is lossy — each save/load cycle introduces quantization error. When
an image is recompressed at the same quality level, the error between the original and
recompressed version reflects how "far" the image is from the JPEG quantization grid.

A pristine image saved once at quality Q, when recompressed at quality Q, will show
low uniform error — the image is already close to its quantized state.

If a region was pasted from a different source (different camera, different compression
history), that region will have a different error signature because it sits at a different
position relative to the Q quantization grid.

### JPEG compression mechanics

JPEG divides the image into 8×8 blocks, applies DCT (Discrete Cosine Transform) to each
block, then quantizes the DCT coefficients using a quality-dependent quantization matrix.
Lower quality = more aggressive quantization = more information loss.

Key forensic implications:
- Each JPEG save operation moves pixel values toward the nearest quantization grid point
- After many saves at quality Q, the image converges and ELA shows zero error
- A composited region that has been through a different quantization history will converge
  at a different rate, creating a detectable differential

### Recommended quality levels

- Q95: Detects heavy editing (compositing from very different sources)
- Q90: Good general-purpose detection level
- Q85: Reveals moderate editing artifacts
- Q75: Sensitive but prone to false positives from natural compression variation

---

## Frequency Domain Techniques

### 2D Discrete Fourier Transform

Every image can be decomposed into a sum of 2D sinusoidal patterns (spatial frequencies).
The DFT represents the image in the frequency domain, where each point (u, v) corresponds
to a sinusoid with horizontal frequency u and vertical frequency v.

F(u,v) = Σ_x Σ_y f(x,y) · exp(-2πi(ux/M + vy/N))

The magnitude |F(u,v)| tells us the amplitude of that frequency component.
The phase ∠F(u,v) tells us the spatial position/alignment.

### Natural image statistics in frequency domain

Natural images follow an approximately 1/f power spectral density — low frequencies
(smooth gradients, large shapes) dominate, and high frequencies (fine detail, noise)
have progressively less energy. This creates the characteristic bright-center, dim-edges
pattern in the magnitude spectrum.

### Hidden pattern detection

A periodic pattern embedded in the image (e.g., a repeating watermark, a grid overlay,
or a regularly-spaced series of dots) produces discrete peaks in the frequency domain
that deviate from the expected 1/f falloff. The position of these peaks directly encodes
the pattern's spatial frequency and orientation:

    spatial_period = image_dimension / distance_from_center

For example, in a 1024-pixel-wide image, a peak at horizontal distance 32 from center
indicates a pattern that repeats every 1024/32 = 32 pixels.

### Phase-based watermarking

Some steganographic techniques modify the phase spectrum rather than the magnitude.
Phase modifications are harder to detect visually (the magnitude spectrum looks normal)
but alter the spatial structure of the image. Phase analysis is included in the pipeline
output for manual inspection.

---

## Statistical Steganalysis

### Shannon entropy

H = -Σ_i p(i) · log₂(p(i))

For an 8-bit channel, maximum entropy is 8.0 bits (perfectly uniform distribution).
Natural images typically fall between 6.0-7.5 bits. Values approaching 8.0 suggest
the channel contains near-random data, which is consistent with encrypted steganographic
payload but is not conclusive on its own.

### Higher-order statistics

Beyond first-order statistics (histogram, mean, variance), steganographic embedding can
be detected by analyzing:

- **Co-occurrence matrices**: How pixel values relate to their neighbors. Embedding
  disrupts local correlations.
- **Difference arrays**: The distribution of differences between adjacent pixels.
  LSB embedding increases the count of differences that are exactly ±1.
- **Markov transition probabilities**: The probability of transitioning from one pixel
  value to the next. Embedding perturbs these transition probabilities.

These higher-order methods are more robust than the chi-square test but require
calibration on a set of known clean images from the same camera/scene type. The current
pipeline focuses on first-order methods for simplicity and generality.

---

## Limitations and Edge Cases

### JPEG artifacts

JPEG compression inherently modifies pixel values and creates block-boundary artifacts.
These modifications can trigger false positives in:
- LSB analysis (JPEG quantization overwrites LSBs)
- Chi-square test (quantization creates artificial value-pair correlations)
- Statistical analysis (quantization changes histogram shape)

For JPEG images, weight ELA and FFT results more heavily than LSB-based tests.
For PNG/TIFF/BMP (lossless) images, LSB and chi-square tests are fully applicable.

### Image scaling and resampling

If the image has been resized (e.g., for web upload), interpolation creates new pixel
values that destroy any previously embedded steganographic content. Analysis of resized
images can only detect steganography that was embedded *after* the resize operation.

### Color space conversion

Steganographic content embedded in RGB space may not survive conversion to/from CMYK,
YCbCr, or other color spaces. If the image has been through format conversion, the
original embedding may be partially or fully destroyed.

### Print-and-scan attacks

Printing an image and scanning it back introduces analog noise that destroys most
digital steganographic content. This is relevant for Kryptos analysis — a photo of
the physical sculpture is equivalent to a "print-and-scan" of whatever digital
information might have been encoded in the copper panels. Digital steg techniques
apply only to the digital photograph itself, not to information in the physical medium.

---

## Academic References

### Foundational papers

- Westfeld, A. & Pfitzmann, A. (1999). "Attacks on Steganographic Systems." *Information
  Hiding*, LNCS 1768. — Introduces the chi-square attack for LSB detection.

- Fridrich, J., Goljan, M., & Du, R. (2001). "Detecting LSB Steganography in Color and
  Grayscale Images." *IEEE Multimedia*, 8(4). — Extends chi-square detection to color
  images and introduces the RS steganalysis method.

- Kharrazi, M., Sencar, H.T., & Memon, N. (2004). "Image Steganography: Concepts and
  Practice." *WSPC Lecture Notes Series*. — Comprehensive survey of embedding and
  detection techniques.

### Advanced steganalysis

- Fridrich, J. & Kodovský, J. (2012). "Rich Models for Steganalysis of Digital Images."
  *IEEE Transactions on Information Forensics and Security*, 7(3). — Introduces the
  Spatial Rich Model (SRM) feature set for universal steganalysis.

- Denemark, T. et al. (2014). "Selection-Channel-Aware Rich Model for Steganalysis of
  Digital Images." *IEEE Workshop on Information Forensic and Security*. — Advances in
  detecting adaptive steganography.

### Error Level Analysis

- Krawetz, N. (2007). "A Picture's Worth... Digital Image Analysis and Forensics."
  *Black Hat Briefings*. — Popularizes ELA for image forensics.

### Frequency domain techniques

- Cox, I.J. et al. (2002). *Digital Watermarking and Steganography*. Morgan Kaufmann.
  — Comprehensive treatment of frequency-domain embedding and detection.
