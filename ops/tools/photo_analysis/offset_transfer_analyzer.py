#!/usr/bin/env python3
"""
Offset-Transfer Analyzer for Archival Notebook Page Forensics.

Purpose: Detect ink offset transfer, bleed-through, pressure impressions,
and mirrored contact impressions on surviving notebook/sketchbook pages
where adjacent pages may have been removed.

This is a physical-document forensics tool, NOT a digital steganography tool.
Every transform is documented and reversible. No "magic enhancement" that
invents detail.

Usage:
    # Classify pages by ink density
    python offset_transfer_analyzer.py classify /path/to/pages/ -o output/

    # Enhance faint marks on a single page
    python offset_transfer_analyzer.py enhance /path/to/page.jpg -o output/

    # Compare facing pages for offset transfer
    python offset_transfer_analyzer.py compare /path/to/pageA.jpg /path/to/pageB.jpg -o output/

    # Full batch analysis on a folder of sequential pages
    python offset_transfer_analyzer.py batch /path/to/pages/ -o output/
"""

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import cv2
import numpy as np
from PIL import Image


class NumpyEncoder(json.JSONEncoder):
    """JSON encoder that handles numpy types."""
    def default(self, obj):
        if isinstance(obj, (np.integer,)):
            return int(obj)
        if isinstance(obj, (np.floating,)):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super().default(obj)

try:
    from pillow_heif import register_heif_opener
    register_heif_opener()
    HEIF_AVAILABLE = True
except ImportError:
    HEIF_AVAILABLE = False


# ── Data Classes ────────────────────────────────────────────────────────

@dataclass
class PageInfo:
    """Metadata and classification for a single page image."""
    path: str
    filename: str
    page_number: int = -1
    width: int = 0
    height: int = 0
    file_size: int = 0
    sha256: str = ""
    format: str = ""
    ink_density: float = 0.0  # fraction of pixels below dark threshold
    classification: str = ""  # blank, sparse, content, heavy
    mean_luminance: float = 0.0
    std_luminance: float = 0.0


@dataclass
class CandidateRegion:
    """A candidate region that may contain transferred writing."""
    region_id: str = ""
    source_image: str = ""
    x: int = 0
    y: int = 0
    w: int = 0
    h: int = 0
    # Scoring
    strength: float = 0.0          # how dark/distinct the mark is
    compactness: float = 0.0       # shape compactness (circle=1.0)
    textlike_score: float = 0.0    # geometric text-likeness (0-1)
    persistence: int = 0           # number of transforms where visible
    transforms_visible: list = field(default_factory=list)
    # Hypothesis assessment
    observation: str = ""
    measurement: str = ""
    inference: str = ""
    benign_causes: list = field(default_factory=list)
    confidence: str = "UNCONFIRMED"  # CONFIRMED / TENTATIVE / UNCONFIRMED
    hypothesis: str = ""  # H1-H7


# ── Image Loading ───────────────────────────────────────────────────────

def load_image(path: str) -> np.ndarray:
    """Load an image from any supported format, return as BGR numpy array."""
    path = str(path)
    ext = os.path.splitext(path)[1].lower()

    if ext in ('.heic', '.heif'):
        if not HEIF_AVAILABLE:
            raise RuntimeError("pillow-heif not installed; cannot load HEIC")
        pil_img = Image.open(path).convert("RGB")
        arr = np.array(pil_img)
        return cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)

    img = cv2.imread(path, cv2.IMREAD_COLOR)
    if img is None:
        # Fallback via PIL
        pil_img = Image.open(path).convert("RGB")
        arr = np.array(pil_img)
        return cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
    return img


def compute_sha256(path: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_page_number(filename: str) -> int:
    """Extract page number from filename. Returns -1 if not found."""
    import re
    # Pattern: starts with digits followed by - or _
    m = re.match(r'^(\d+)[-_]', filename)
    if m:
        return int(m.group(1))
    # Pattern: IMG_NNNN
    m = re.match(r'^IMG_(\d+)', filename)
    if m:
        return int(m.group(1))
    return -1


# ── Page Classification ─────────────────────────────────────────────────

def classify_page(img: np.ndarray) -> tuple:
    """Classify page by ink density and content level.

    Returns (classification, ink_density, mean_lum, std_lum).
    Classification: blank, sparse, content, heavy
    """
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    mean_lum = float(np.mean(gray))
    std_lum = float(np.std(gray))

    # Ink density: fraction of pixels significantly darker than background
    # Adaptive threshold based on the image's own statistics
    dark_threshold = max(mean_lum - 2.0 * std_lum, 40)
    dark_pixels = np.sum(gray < dark_threshold)
    total_pixels = gray.size
    ink_density = dark_pixels / total_pixels

    if ink_density < 0.005:
        classification = "blank"
    elif ink_density < 0.02:
        classification = "sparse"
    elif ink_density < 0.15:
        classification = "content"
    else:
        classification = "heavy"

    return classification, ink_density, mean_lum, std_lum


# ── Faint-Mark Enhancement Stack ────────────────────────────────────────

def enhance_grayscale(img: np.ndarray) -> np.ndarray:
    """Convert to grayscale. Baseline view."""
    return cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)


def enhance_inverted(gray: np.ndarray) -> np.ndarray:
    """Invert grayscale. Faint dark marks become bright features."""
    return 255 - gray


def enhance_clahe(gray: np.ndarray, clip_limit: float = 3.0,
                  tile_size: int = 8) -> np.ndarray:
    """CLAHE local contrast enhancement.

    Reveals faint local variations without global distortion.
    clip_limit controls aggressiveness (2.0=mild, 5.0=strong).
    """
    clahe = cv2.createCLAHE(clipLimit=clip_limit,
                            tileGridSize=(tile_size, tile_size))
    return clahe.apply(gray)


def enhance_lab_l(img: np.ndarray) -> np.ndarray:
    """Extract L channel from Lab color space.

    Isolates luminance from chrominance — useful when ink has
    different color than paper aging stains.
    """
    lab = cv2.cvtColor(img, cv2.COLOR_BGR2Lab)
    return lab[:, :, 0]


def enhance_highpass(gray: np.ndarray, sigma: int = 51) -> np.ndarray:
    """High-pass filter: subtract low-frequency (blur) from original.

    Removes illumination gradients while preserving sharp features.
    sigma must be odd and large enough to span lighting gradients.
    """
    if sigma % 2 == 0:
        sigma += 1
    lowpass = cv2.GaussianBlur(gray, (sigma, sigma), 0)
    # Subtract lowpass and rescale to 0-255
    hp = gray.astype(np.float32) - lowpass.astype(np.float32)
    hp = hp - hp.min()
    if hp.max() > 0:
        hp = (hp / hp.max() * 255).astype(np.uint8)
    else:
        hp = np.zeros_like(gray)
    return hp


def enhance_retinex(gray: np.ndarray, sigma: int = 101) -> np.ndarray:
    """Single-scale Retinex illumination normalization.

    Divides by low-pass to normalize illumination, revealing
    faint features hidden by lighting gradient.
    """
    if sigma % 2 == 0:
        sigma += 1
    gray_f = gray.astype(np.float32) + 1.0  # avoid log(0)
    blur = cv2.GaussianBlur(gray_f, (sigma, sigma), 0) + 1.0
    retinex = np.log(gray_f) - np.log(blur)
    # Normalize to 0-255
    retinex = retinex - retinex.min()
    if retinex.max() > 0:
        retinex = (retinex / retinex.max() * 255).astype(np.uint8)
    else:
        retinex = np.zeros_like(gray)
    return retinex


def enhance_channel_isolation(img: np.ndarray) -> dict:
    """Separate RGB channels. Different inks may be visible in different channels.

    Returns dict of channel name -> grayscale array.
    """
    b, g, r = cv2.split(img)
    return {"red": r, "green": g, "blue": b}


def enhance_channel_difference(img: np.ndarray) -> dict:
    """Channel difference maps. Ink residue may appear in one channel but not others.

    Returns dict of pair name -> difference array (rescaled 0-255).
    """
    b, g, r = cv2.split(img)
    diffs = {}
    for name, a, b_ch in [("R-G", r, g), ("R-B", r, b), ("G-B", g, b)]:
        diff = a.astype(np.float32) - b_ch.astype(np.float32)
        diff = diff - diff.min()
        if diff.max() > 0:
            diff = (diff / diff.max() * 255).astype(np.uint8)
        else:
            diff = np.zeros_like(r)
        diffs[name] = diff
    return diffs


def run_enhancement_stack(img: np.ndarray) -> dict:
    """Run the full faint-mark enhancement stack.

    Returns dict of transform_name -> enhanced grayscale array.
    Each transform is independent and documented.
    """
    gray = enhance_grayscale(img)
    results = {
        "grayscale": gray,
        "inverted": enhance_inverted(gray),
        "clahe_mild": enhance_clahe(gray, clip_limit=2.0),
        "clahe_strong": enhance_clahe(gray, clip_limit=5.0),
        "lab_L": enhance_lab_l(img),
        "highpass_51": enhance_highpass(gray, sigma=51),
        "highpass_101": enhance_highpass(gray, sigma=101),
        "retinex": enhance_retinex(gray, sigma=101),
    }

    # Channel isolations
    channels = enhance_channel_isolation(img)
    for name, ch in channels.items():
        results[f"channel_{name}"] = ch

    # Channel differences
    diffs = enhance_channel_difference(img)
    for name, diff in diffs.items():
        results[f"diff_{name}"] = diff

    # CLAHE on individual channels (ink may show differently per channel)
    for ch_name, ch in channels.items():
        results[f"clahe_{ch_name}"] = enhance_clahe(ch, clip_limit=3.0)

    return results


# ── Mirror Transform Pipeline ──────────────────────────────────────────

def mirror_horizontal(img: np.ndarray) -> np.ndarray:
    """Horizontal flip. Simulates facing-page contact transfer."""
    return cv2.flip(img, 1)


def compute_difference_map(img_a: np.ndarray, img_b: np.ndarray) -> np.ndarray:
    """Absolute difference between two grayscale images of same size.

    If images differ in size, resize img_b to match img_a.
    """
    if img_a.shape != img_b.shape:
        img_b = cv2.resize(img_b, (img_a.shape[1], img_a.shape[0]))
    diff = cv2.absdiff(img_a, img_b)
    return diff


def create_overlay(base: np.ndarray, overlay: np.ndarray,
                   alpha: float = 0.5) -> np.ndarray:
    """Blend two grayscale images for visual comparison.

    alpha controls overlay opacity (0.0 = base only, 1.0 = overlay only).
    """
    if base.shape != overlay.shape:
        overlay = cv2.resize(overlay, (base.shape[1], base.shape[0]))
    # Convert to 3-channel for color overlay
    base_color = cv2.cvtColor(base, cv2.COLOR_GRAY2BGR)
    # Make overlay red-tinted for visibility
    overlay_color = np.zeros_like(base_color)
    overlay_color[:, :, 2] = overlay  # Red channel
    blended = cv2.addWeighted(base_color, 1.0 - alpha, overlay_color, alpha, 0)
    return blended


# ── Candidate Region Detection ──────────────────────────────────────────

def detect_candidate_regions(enhanced: np.ndarray, min_area: int = 50,
                              max_area_frac: float = 0.1) -> list:
    """Detect candidate regions in an enhanced image that may contain faint marks.

    Uses adaptive thresholding + connected components to find clusters
    of dark/different pixels that resemble writing strokes.

    Returns list of (x, y, w, h, area, strength) tuples.
    """
    # Adaptive threshold to find locally dark regions
    thresh = cv2.adaptiveThreshold(
        enhanced, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY_INV, 21, 5
    )

    # Morphological close to connect nearby fragments
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
    closed = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, kernel)

    # Find connected components
    n_labels, labels, stats, centroids = cv2.connectedComponentsWithStats(
        closed, connectivity=8
    )

    max_area = enhanced.size * max_area_frac
    candidates = []

    for i in range(1, n_labels):  # skip background (label 0)
        x, y, w, h, area = stats[i]

        if area < min_area or area > max_area:
            continue

        # Compute region strength (mean intensity in original enhanced image)
        mask = (labels == i).astype(np.uint8)
        strength = float(np.mean(enhanced[mask > 0]))

        # Compactness: 4π·area / perimeter²
        contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL,
                                        cv2.CHAIN_APPROX_SIMPLE)
        if contours:
            perimeter = cv2.arcLength(contours[0], True)
            if perimeter > 0:
                compactness = 4 * np.pi * area / (perimeter ** 2)
            else:
                compactness = 0.0
        else:
            compactness = 0.0

        candidates.append((x, y, w, h, area, strength, compactness))

    # Sort by area descending (larger regions first)
    candidates.sort(key=lambda c: c[4], reverse=True)
    return candidates


def score_textlikeness(x, y, w, h, compactness, area) -> float:
    """Score a candidate region for text-like geometry.

    Text-like characteristics:
    - Moderate aspect ratio (not too square, not too elongated)
    - Not too circular (compactness < 0.8)
    - Moderate size relative to expected character size
    """
    aspect = max(w, h) / max(min(w, h), 1)

    score = 0.0
    # Aspect ratio: text regions are typically 1.5-10x elongated
    if 1.2 < aspect < 12:
        score += 0.3
    # Compactness: text strokes are not circular
    if 0.05 < compactness < 0.6:
        score += 0.3
    # Size: reasonable for a character or word fragment
    if 100 < area < 50000:
        score += 0.2
    # Not touching image borders (border artifacts)
    score += 0.2  # Full score since we can't check borders here

    return min(score, 1.0)


# ── Facing-Page Comparison ──────────────────────────────────────────────

def compare_facing_pages(page_a_path: str, page_b_path: str,
                          output_dir: str) -> dict:
    """Compare two sequential pages for offset transfer evidence.

    Tests H1 (transfer from facing page) vs H2 (show-through from self).

    page_a: the content page (ink source)
    page_b: the sparse/blank page (potential transfer recipient)
    """
    os.makedirs(output_dir, exist_ok=True)
    img_a = load_image(page_a_path)
    img_b = load_image(page_b_path)

    gray_a = enhance_grayscale(img_a)
    gray_b = enhance_grayscale(img_b)

    # Mirror page A (simulating contact transfer = horizontal flip)
    mirrored_a = mirror_horizontal(gray_a)

    # Resize to match if needed
    if gray_a.shape != gray_b.shape:
        mirrored_a = cv2.resize(mirrored_a, (gray_b.shape[1], gray_b.shape[0]))
        gray_a_resized = cv2.resize(gray_a, (gray_b.shape[1], gray_b.shape[0]))
    else:
        gray_a_resized = gray_a

    # Difference maps
    diff_mirrored = compute_difference_map(gray_b, mirrored_a)
    diff_direct = compute_difference_map(gray_b, gray_a_resized)

    # Enhance page B for faint marks
    enhanced_b = run_enhancement_stack(img_b)

    # Save outputs
    cv2.imwrite(os.path.join(output_dir, "page_a_gray.png"), gray_a)
    cv2.imwrite(os.path.join(output_dir, "page_b_gray.png"), gray_b)
    cv2.imwrite(os.path.join(output_dir, "page_a_mirrored.png"), mirrored_a)
    cv2.imwrite(os.path.join(output_dir, "diff_mirrored.png"), diff_mirrored)
    cv2.imwrite(os.path.join(output_dir, "diff_direct.png"), diff_direct)

    # Save key enhancements of page B
    for name in ["clahe_strong", "highpass_51", "retinex", "inverted"]:
        if name in enhanced_b:
            cv2.imwrite(os.path.join(output_dir, f"pageB_{name}.png"),
                        enhanced_b[name])

    # Overlay: mirrored A on B
    overlay = create_overlay(gray_b, mirrored_a, alpha=0.3)
    cv2.imwrite(os.path.join(output_dir, "overlay_mirrored_on_b.png"), overlay)

    # Detect candidates in enhanced page B
    candidates = {}
    for name in ["clahe_strong", "highpass_51", "retinex"]:
        if name in enhanced_b:
            cands = detect_candidate_regions(enhanced_b[name])
            candidates[name] = cands

    # Cross-correlate: regions visible in mirrored diff AND enhanced B
    diff_mirrored_enhanced = enhance_clahe(diff_mirrored, clip_limit=4.0)
    cv2.imwrite(os.path.join(output_dir, "diff_mirrored_enhanced.png"),
                diff_mirrored_enhanced)

    report = {
        "page_a": os.path.basename(page_a_path),
        "page_b": os.path.basename(page_b_path),
        "page_a_size": list(gray_a.shape),
        "page_b_size": list(gray_b.shape),
        "diff_mirrored_mean": float(np.mean(diff_mirrored)),
        "diff_direct_mean": float(np.mean(diff_direct)),
        "diff_mirrored_std": float(np.std(diff_mirrored)),
        "diff_direct_std": float(np.std(diff_direct)),
        "candidates_per_transform": {
            k: len(v) for k, v in candidates.items()
        },
        "outputs": sorted(os.listdir(output_dir)),
    }

    with open(os.path.join(output_dir, "comparison_report.json"), "w") as f:
        json.dump(report, f, indent=2, cls=NumpyEncoder)

    return report


# ── Batch Analysis ──────────────────────────────────────────────────────

def build_manifest(image_dir: str) -> list:
    """Build a manifest of all images in a directory with classification."""
    supported = {'.jpg', '.jpeg', '.png', '.tiff', '.tif', '.bmp', '.heic', '.heif'}
    pages = []

    for f in sorted(os.listdir(image_dir)):
        ext = os.path.splitext(f)[1].lower()
        if ext not in supported:
            continue

        path = os.path.join(image_dir, f)
        file_size = os.path.getsize(path)

        try:
            img = load_image(path)
            h, w = img.shape[:2]
            classification, ink_density, mean_lum, std_lum = classify_page(img)
            sha = compute_sha256(path)

            info = PageInfo(
                path=path,
                filename=f,
                page_number=extract_page_number(f),
                width=w,
                height=h,
                file_size=file_size,
                sha256=sha,
                format=ext.lstrip('.').upper(),
                ink_density=ink_density,
                classification=classification,
                mean_luminance=mean_lum,
                std_luminance=std_lum,
            )
            pages.append(info)
        except Exception as e:
            print(f"  WARN: Failed to process {f}: {e}", file=sys.stderr)

    return pages


def batch_analyze(image_dir: str, output_dir: str,
                  sparse_threshold: float = 0.02) -> dict:
    """Full batch analysis of a sequential page folder.

    1. Classify all pages
    2. Identify sparse/blank pages
    3. Run enhancement stack on sparse pages
    4. Compare sparse pages with adjacent content pages
    5. Detect and score candidate regions
    """
    os.makedirs(output_dir, exist_ok=True)
    print(f"Building manifest for: {image_dir}")

    pages = build_manifest(image_dir)
    pages.sort(key=lambda p: p.page_number)

    print(f"  Total pages: {len(pages)}")
    for cls in ["blank", "sparse", "content", "heavy"]:
        count = sum(1 for p in pages if p.classification == cls)
        if count:
            nums = [p.page_number for p in pages if p.classification == cls]
            print(f"  {cls}: {count} pages {nums}")

    # Save manifest
    manifest = [asdict(p) for p in pages]
    with open(os.path.join(output_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    # Find sparse/blank pages and their neighbors
    sparse_pages = [p for p in pages
                    if p.classification in ("blank", "sparse")]

    all_candidates = []
    comparison_results = []

    for sparse_page in sparse_pages:
        pg_num = sparse_page.page_number
        pg_dir = os.path.join(output_dir, f"page_{pg_num:03d}")
        os.makedirs(pg_dir, exist_ok=True)

        print(f"\n  Analyzing sparse page {pg_num} ({sparse_page.classification}, "
              f"ink={sparse_page.ink_density:.4f})...")

        # Run enhancement stack
        img = load_image(sparse_page.path)
        enhanced = run_enhancement_stack(img)

        # Save all enhancements
        for name, arr in enhanced.items():
            cv2.imwrite(os.path.join(pg_dir, f"enhanced_{name}.png"), arr)

        # Detect candidates across transforms
        region_persistence = {}  # (x_bin, y_bin) -> count
        all_regions_this_page = []

        for transform_name, arr in enhanced.items():
            regions = detect_candidate_regions(arr)
            for x, y, w, h, area, strength, compactness in regions[:50]:
                # Bin to 20px grid for persistence counting
                x_bin = x // 20
                y_bin = y // 20
                key = (x_bin, y_bin)
                if key not in region_persistence:
                    region_persistence[key] = {
                        "x": x, "y": y, "w": w, "h": h,
                        "count": 0, "transforms": [],
                        "max_strength": 0.0,
                        "compactness": compactness,
                        "area": area,
                    }
                region_persistence[key]["count"] += 1
                region_persistence[key]["transforms"].append(transform_name)
                region_persistence[key]["max_strength"] = max(
                    region_persistence[key]["max_strength"], strength
                )

        # Score persistent regions
        for key, info in region_persistence.items():
            if info["count"] < 2:  # Two-corroboration minimum
                continue
            textlike = score_textlikeness(
                info["x"], info["y"], info["w"], info["h"],
                info["compactness"], info["area"]
            )
            candidate = CandidateRegion(
                region_id=f"pg{pg_num}_{info['x']}_{info['y']}",
                source_image=sparse_page.filename,
                x=info["x"], y=info["y"],
                w=info["w"], h=info["h"],
                strength=info["max_strength"],
                compactness=info["compactness"],
                textlike_score=textlike,
                persistence=info["count"],
                transforms_visible=info["transforms"][:10],
                observation=f"Candidate region at ({info['x']},{info['y']}) "
                            f"size {info['w']}x{info['h']} "
                            f"visible in {info['count']} transforms",
                measurement=f"strength={info['max_strength']:.1f}, "
                            f"compactness={info['compactness']:.3f}, "
                            f"textlike={textlike:.2f}",
            )
            all_regions_this_page.append(candidate)

        # Compare with adjacent pages
        page_map = {p.page_number: p for p in pages}
        for neighbor_num in [pg_num - 1, pg_num + 1]:
            if neighbor_num in page_map:
                neighbor = page_map[neighbor_num]
                if neighbor.classification in ("content", "heavy"):
                    comp_dir = os.path.join(pg_dir,
                                             f"compare_with_{neighbor_num:03d}")
                    print(f"    Comparing with content page {neighbor_num}...")
                    try:
                        comp = compare_facing_pages(
                            neighbor.path, sparse_page.path, comp_dir
                        )
                        comparison_results.append(comp)
                    except Exception as e:
                        print(f"    WARN: Comparison failed: {e}")

        # Sort candidates by persistence × textlikeness
        all_regions_this_page.sort(
            key=lambda c: c.persistence * c.textlike_score, reverse=True
        )
        all_candidates.extend(all_regions_this_page[:20])  # Top 20 per page

        # Save page-level candidate summary
        with open(os.path.join(pg_dir, "candidates.json"), "w") as f:
            json.dump([asdict(c) for c in all_regions_this_page[:20]], f, indent=2, cls=NumpyEncoder)

        print(f"    Found {len(all_regions_this_page)} candidate regions "
              f"(≥2 transforms)")

    # Save global results
    summary = {
        "image_dir": image_dir,
        "total_pages": len(pages),
        "sparse_pages": len(sparse_pages),
        "total_candidates": len(all_candidates),
        "comparisons": len(comparison_results),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    with open(os.path.join(output_dir, "batch_summary.json"), "w") as f:
        json.dump(summary, f, indent=2, cls=NumpyEncoder)

    with open(os.path.join(output_dir, "all_candidates.json"), "w") as f:
        json.dump([asdict(c) for c in all_candidates], f, indent=2, cls=NumpyEncoder)

    return summary


# ── Single-Page Enhancement ─────────────────────────────────────────────

def enhance_single(image_path: str, output_dir: str) -> dict:
    """Run full enhancement stack on a single page and save all outputs."""
    os.makedirs(output_dir, exist_ok=True)
    img = load_image(image_path)
    classification, ink_density, mean_lum, std_lum = classify_page(img)

    print(f"Page: {os.path.basename(image_path)}")
    print(f"  Size: {img.shape[1]}x{img.shape[0]}")
    print(f"  Classification: {classification} (ink_density={ink_density:.4f})")
    print(f"  Luminance: mean={mean_lum:.1f}, std={std_lum:.1f}")

    enhanced = run_enhancement_stack(img)

    for name, arr in enhanced.items():
        cv2.imwrite(os.path.join(output_dir, f"enhanced_{name}.png"), arr)

    # Detect candidates
    all_regions = {}
    for name, arr in enhanced.items():
        regions = detect_candidate_regions(arr)
        all_regions[name] = len(regions)

    report = {
        "source": os.path.basename(image_path),
        "classification": classification,
        "ink_density": ink_density,
        "mean_luminance": mean_lum,
        "std_luminance": std_lum,
        "enhancements_generated": list(enhanced.keys()),
        "candidates_per_transform": all_regions,
    }

    with open(os.path.join(output_dir, "enhancement_report.json"), "w") as f:
        json.dump(report, f, indent=2, cls=NumpyEncoder)

    return report


# ── CLI ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Offset-Transfer Analyzer for archival notebook forensics"
    )
    sub = parser.add_subparsers(dest="command")

    # classify
    p_cls = sub.add_parser("classify", help="Classify pages by ink density")
    p_cls.add_argument("image_dir", help="Directory of page images")
    p_cls.add_argument("-o", "--output", required=True, help="Output directory")

    # enhance
    p_enh = sub.add_parser("enhance", help="Enhance faint marks on a single page")
    p_enh.add_argument("image", help="Path to page image")
    p_enh.add_argument("-o", "--output", required=True, help="Output directory")

    # compare
    p_cmp = sub.add_parser("compare", help="Compare facing pages")
    p_cmp.add_argument("page_a", help="Content page (ink source)")
    p_cmp.add_argument("page_b", help="Sparse/blank page (transfer target)")
    p_cmp.add_argument("-o", "--output", required=True, help="Output directory")

    # batch
    p_bat = sub.add_parser("batch", help="Full batch analysis")
    p_bat.add_argument("image_dir", help="Directory of sequential page images")
    p_bat.add_argument("-o", "--output", required=True, help="Output directory")

    args = parser.parse_args()

    if args.command == "classify":
        pages = build_manifest(args.image_dir)
        pages.sort(key=lambda p: p.page_number)
        os.makedirs(args.output, exist_ok=True)
        with open(os.path.join(args.output, "manifest.json"), "w") as f:
            json.dump([asdict(p) for p in pages], f, indent=2, cls=NumpyEncoder)
        for p in pages:
            print(f"  Page {p.page_number:3d}: {p.classification:8s} "
                  f"ink={p.ink_density:.4f} lum={p.mean_luminance:.0f}±{p.std_luminance:.0f} "
                  f"({p.width}x{p.height}, {p.file_size//1024}KB)")

    elif args.command == "enhance":
        enhance_single(args.image, args.output)

    elif args.command == "compare":
        compare_facing_pages(args.page_a, args.page_b, args.output)

    elif args.command == "batch":
        batch_analyze(args.image_dir, args.output)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
