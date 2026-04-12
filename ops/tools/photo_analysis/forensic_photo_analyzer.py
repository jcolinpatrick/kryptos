#!/usr/bin/env python3
"""
forensic_photo_analyzer.py — Comprehensive Forensic Photo Analysis Tool

Unified pipeline for forensic image analysis, photo comparison, and
perspective correction. Designed for cryptanalytic photo investigation,
particularly Kryptos K4 steganographic analysis.

Subcommands:
    analyze   Run forensic analysis pipeline on a single image
    compare   Align and diff two images of the same subject
    correct   Apply perspective correction to an angled photo

Usage:
    python forensic_photo_analyzer.py analyze <image> [-o DIR] [-m mod1,mod2]
    python forensic_photo_analyzer.py compare <reference> <candidate> [-o DIR]
    python forensic_photo_analyzer.py correct <image> [-c X,Y X,Y X,Y X,Y] [--auto] [-o PATH]
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Sequence

import cv2
import numpy as np
from PIL import Image, ExifTags, ImageChops

# ---------------------------------------------------------------------------
# Optional dependency detection — modules degrade gracefully
# ---------------------------------------------------------------------------

try:
    from scipy import stats as sp_stats
    from scipy.stats import chi2 as scipy_chi2
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

try:
    import exifread
    HAS_EXIFREAD = True
except ImportError:
    HAS_EXIFREAD = False

try:
    import pytesseract
    HAS_TESSERACT = True
except ImportError:
    HAS_TESSERACT = False


SUPPORTED_EXTS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".webp"}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _shannon_entropy(channel: np.ndarray) -> float:
    """Shannon entropy of a single-channel image in bits per byte."""
    hist = cv2.calcHist([channel], [0], None, [256], [0, 256]).flatten()
    hist = hist[hist > 0]
    probs = hist / hist.sum()
    return float(-np.sum(probs * np.log2(probs)))


def _normalize_u8(arr: np.ndarray) -> np.ndarray:
    """Normalize array to 0-255 uint8 for display."""
    arr = arr.astype(np.float32)
    mn, mx = float(arr.min()), float(arr.max())
    if mx - mn < 1e-9:
        return np.zeros(arr.shape[:2], dtype=np.uint8)
    return np.clip((arr - mn) / (mx - mn) * 255.0, 0, 255).astype(np.uint8)


def _extract_lsb_ascii(channel: np.ndarray, min_run: int = 8) -> str:
    """Extract LSBs row-major and find the longest printable ASCII run."""
    flat = channel.flatten()
    bits = flat & 1
    n_bytes = len(bits) // 8
    if n_bytes == 0:
        return ""
    bits_trimmed = bits[:n_bytes * 8].reshape(-1, 8)
    powers = np.array([128, 64, 32, 16, 8, 4, 2, 1], dtype=np.uint8)
    byte_vals = np.sum(bits_trimmed * powers, axis=1).astype(np.uint8)

    printable_mask = (byte_vals >= 0x20) & (byte_vals <= 0x7E)
    best_start, best_len, curr_start, curr_len = 0, 0, 0, 0
    for i, is_print in enumerate(printable_mask):
        if is_print:
            if curr_len == 0:
                curr_start = i
            curr_len += 1
        else:
            if curr_len > best_len:
                best_start, best_len = curr_start, curr_len
            curr_len = 0
    if curr_len > best_len:
        best_start, best_len = curr_start, curr_len

    if best_len >= min_run:
        return bytes(byte_vals[best_start:best_start + best_len]).decode(
            "ascii", errors="replace"
        )
    return ""


def _save_histogram_plot(
    img_bgr: np.ndarray, img_gray: np.ndarray, path: Path
) -> None:
    """Save a composite histogram image using OpenCV drawing (no matplotlib)."""
    hist_h, hist_w = 300, 512
    canvas = np.ones((hist_h * 2, hist_w, 3), dtype=np.uint8) * 255

    colors = [(255, 0, 0), (0, 255, 0), (0, 0, 255)]
    for i, color in enumerate(colors):
        hist = cv2.calcHist([img_bgr], [i], None, [256], [0, 256]).flatten()
        cv2.normalize(hist, hist, 0, hist_h - 20, cv2.NORM_MINMAX)
        for x in range(1, 256):
            cv2.line(
                canvas,
                (x * 2 - 2, hist_h - int(hist[x - 1])),
                (x * 2, hist_h - int(hist[x])),
                color, 1,
            )

    hist_gray = cv2.calcHist([img_gray], [0], None, [256], [0, 256]).flatten()
    cv2.normalize(hist_gray, hist_gray, 0, hist_h - 20, cv2.NORM_MINMAX)
    for x in range(1, 256):
        cv2.line(
            canvas,
            (x * 2 - 2, hist_h * 2 - int(hist_gray[x - 1])),
            (x * 2, hist_h * 2 - int(hist_gray[x])),
            (80, 80, 80), 1,
        )

    cv2.imwrite(str(path), canvas)


def _check_grid_regularity(
    centroids: list[tuple[float, float]], tolerance: float = 0.15
) -> dict[str, Any]:
    """Check if 2D points exhibit grid-like regular spacing."""
    if len(centroids) < 4:
        return {"is_regular": False, "reason": "too few points"}

    xs = sorted(set(round(c[0]) for c in centroids))
    ys = sorted(set(round(c[1]) for c in centroids))

    x_diffs = np.diff(xs).astype(np.float64)
    y_diffs = np.diff(ys).astype(np.float64)

    result: dict[str, Any] = {"is_regular": False}

    if len(x_diffs) > 2:
        x_cv = (
            float(np.std(x_diffs) / np.mean(x_diffs))
            if np.mean(x_diffs) > 0 else 999
        )
        if x_cv < tolerance:
            result["is_regular"] = True
            result["spacing"] = float(np.mean(x_diffs))
            result["axis"] = "horizontal"
            result["cv"] = x_cv

    if len(y_diffs) > 2:
        y_cv = (
            float(np.std(y_diffs) / np.mean(y_diffs))
            if np.mean(y_diffs) > 0 else 999
        )
        if y_cv < tolerance:
            result["is_regular"] = True
            result["spacing"] = float(np.mean(y_diffs))
            result["axis"] = (
                "both" if result.get("axis") else "vertical"
            )
            result["cv"] = y_cv

    return result


# ===================================================================
#  ANALYSIS MODULES — Each returns a dict with "module", "findings",
#  and optionally "outputs" (file paths of generated images).
# ===================================================================

def run_metadata(
    image_path: Path, img_bgr: np.ndarray,
    img_gray: np.ndarray, output_dir: Path,
) -> dict[str, Any]:
    """Extract EXIF, PIL, and embedded metadata."""
    results: dict[str, Any] = {"module": "metadata", "findings": []}
    metadata: dict[str, str] = {}

    # EXIF via exifread (preferred — more complete than PIL)
    if HAS_EXIFREAD:
        try:
            with open(image_path, "rb") as f:
                tags = exifread.process_file(f, details=True)
            for tag_name, tag_value in sorted(tags.items()):
                if tag_name == "JPEGThumbnail":
                    continue  # handled separately
                metadata[tag_name] = str(tag_value)
        except Exception as exc:
            results["findings"].append(f"EXIF extraction error: {exc}")
    else:
        results["findings"].append(
            "exifread not installed — using PIL EXIF only (less complete)"
        )

    # PIL metadata (catches things exifread misses like PNG text chunks)
    try:
        pil_img = Image.open(image_path)
        for key, val in pil_img.info.items():
            metadata[f"PIL:{key}"] = str(val)[:500]

        # PIL EXIF as fallback
        raw_exif = pil_img.getexif()
        if raw_exif:
            for tag_id, value in raw_exif.items():
                tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                try:
                    if isinstance(value, bytes):
                        value = value[:64].hex()
                    elif isinstance(value, (tuple, list)):
                        value = list(value)[:16]
                    metadata[f"PIL_EXIF:{tag}"] = str(value)
                except Exception:
                    metadata[f"PIL_EXIF:{tag}"] = str(value)
    except Exception as exc:
        results["findings"].append(f"PIL metadata error: {exc}")

    # Thumbnail consistency check
    if HAS_EXIFREAD:
        try:
            with open(image_path, "rb") as f:
                tags = exifread.process_file(f, details=True)
            if "JPEGThumbnail" in tags:
                results["findings"].append(
                    "ALERT: Embedded JPEG thumbnail found — "
                    "verify it matches the main image"
                )
                thumb_path = output_dir / "metadata_thumbnail.jpg"
                with open(thumb_path, "wb") as f:
                    f.write(tags["JPEGThumbnail"])
                results["thumbnail_saved"] = str(thumb_path)
        except Exception:
            pass

    results["metadata"] = metadata
    results["tag_count"] = len(metadata)

    meta_path = output_dir / "metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    results["output_file"] = str(meta_path)

    if len(metadata) == 0:
        results["findings"].append("No metadata found in the file.")
    else:
        results["findings"].append(
            f"Extracted {len(metadata)} metadata fields."
        )

    return results


def run_statistical(
    image_path: Path, img_bgr: np.ndarray,
    img_gray: np.ndarray, output_dir: Path,
) -> dict[str, Any]:
    """Pixel intensity statistics, histograms, and distribution analysis."""
    results: dict[str, Any] = {"module": "statistical", "findings": []}

    if not HAS_SCIPY:
        results["findings"].append(
            "scipy not installed — skewness/kurtosis unavailable"
        )

    channel_names = ["Blue", "Green", "Red"]
    channel_stats = {}

    for i, name in enumerate(channel_names):
        ch = img_bgr[:, :, i].flatten().astype(np.float64)
        stats = {
            "mean": float(np.mean(ch)),
            "std": float(np.std(ch)),
            "median": float(np.median(ch)),
            "entropy": float(_shannon_entropy(img_bgr[:, :, i])),
            "min": int(np.min(ch)),
            "max": int(np.max(ch)),
        }
        if HAS_SCIPY:
            stats["skewness"] = float(sp_stats.skew(ch))
            stats["kurtosis"] = float(sp_stats.kurtosis(ch))
        channel_stats[name] = stats

    # Grayscale
    gray_flat = img_gray.flatten().astype(np.float64)
    gray_stats = {
        "mean": float(np.mean(gray_flat)),
        "std": float(np.std(gray_flat)),
        "median": float(np.median(gray_flat)),
        "entropy": float(_shannon_entropy(img_gray)),
        "min": int(np.min(gray_flat)),
        "max": int(np.max(gray_flat)),
    }
    if HAS_SCIPY:
        gray_stats["skewness"] = float(sp_stats.skew(gray_flat))
        gray_stats["kurtosis"] = float(sp_stats.kurtosis(gray_flat))
    channel_stats["Grayscale"] = gray_stats

    # Additional image-level metrics
    laplacian_var = float(cv2.Laplacian(img_gray, cv2.CV_64F).var())
    edges = cv2.Canny(img_gray, 80, 180)
    edge_dens = float(np.count_nonzero(edges) / edges.size)

    p1, p5, p50, p95, p99 = np.percentile(img_gray, [1, 5, 50, 95, 99])
    dark_frac = float(np.mean(img_gray <= 2))
    bright_frac = float(np.mean(img_gray >= 253))

    results["channel_stats"] = channel_stats
    results["sharpness_laplacian_var"] = laplacian_var
    results["edge_density"] = edge_dens
    results["dynamic_range"] = {
        "p01": float(p1), "p05": float(p5), "p50": float(p50),
        "p95": float(p95), "p99": float(p99),
    }
    results["clipped"] = {
        "dark_fraction": dark_frac, "bright_fraction": bright_frac,
    }

    # Flag anomalies
    for name, s in channel_stats.items():
        if HAS_SCIPY and abs(s.get("skewness", 0)) > 2.0:
            results["findings"].append(
                f"ALERT: {name} channel has high skewness "
                f"({s['skewness']:.3f}) — unusual distribution shape"
            )
        if s["entropy"] > 7.5:
            results["findings"].append(
                f"ALERT: {name} channel entropy is {s['entropy']:.3f} "
                "bits/byte — near-maximum, may indicate embedded data"
            )

    if laplacian_var < 40:
        results["findings"].append(
            f"Image appears soft or blurred (sharpness {laplacian_var:.1f})."
        )
    elif laplacian_var > 120:
        results["findings"].append(
            f"Image is sharp for structural review "
            f"(sharpness {laplacian_var:.1f})."
        )

    if bright_frac > 0.03:
        results["findings"].append(
            f"ALERT: Highlight clipping is non-trivial "
            f"({bright_frac:.2%}); glare may distort forensic layers."
        )
    if dark_frac > 0.03:
        results["findings"].append(
            f"ALERT: Shadow clipping is non-trivial "
            f"({dark_frac:.2%}); dark regions may conceal detail."
        )

    _save_histogram_plot(img_bgr, img_gray, output_dir / "histograms.png")
    results["outputs"] = [str(output_dir / "histograms.png")]

    return results


def run_channel(
    image_path: Path, img_bgr: np.ndarray,
    img_gray: np.ndarray, output_dir: Path,
) -> dict[str, Any]:
    """Separate RGB + HSV channels and compute inter-channel difference maps."""
    results: dict[str, Any] = {
        "module": "channel", "findings": [], "outputs": [],
    }

    for i, name in enumerate(["blue", "green", "red"]):
        p = output_dir / f"channel_{name}.png"
        cv2.imwrite(str(p), img_bgr[:, :, i])
        results["outputs"].append(str(p))

    hsv = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2HSV)
    for i, name in enumerate(["hue", "saturation", "value"]):
        p = output_dir / f"channel_{name}.png"
        cv2.imwrite(str(p), hsv[:, :, i])
        results["outputs"].append(str(p))

    b = img_bgr[:, :, 0].astype(np.int16)
    g = img_bgr[:, :, 1].astype(np.int16)
    r = img_bgr[:, :, 2].astype(np.int16)

    for label, diff in [("diff_RG", r - g), ("diff_RB", r - b),
                        ("diff_GB", g - b)]:
        norm = cv2.normalize(
            diff.astype(np.float32), None, 0, 255, cv2.NORM_MINMAX,
        ).astype(np.uint8)
        p = output_dir / f"{label}.png"
        cv2.imwrite(str(p), norm)
        results["outputs"].append(str(p))

        diff_entropy = _shannon_entropy(norm)
        if diff_entropy < 3.0:
            results["findings"].append(
                f"NOTE: {label} difference map has low entropy "
                f"({diff_entropy:.2f}) — highly uniform chromatic relationship"
            )

    return results


def run_lsb(
    image_path: Path, img_bgr: np.ndarray,
    img_gray: np.ndarray, output_dir: Path,
) -> dict[str, Any]:
    """Extract least significant bit planes (bits 0-3) with ASCII decoding."""
    results: dict[str, Any] = {
        "module": "lsb", "findings": [], "outputs": [],
    }

    for ch_idx, ch_name in enumerate(["blue", "green", "red"]):
        channel = img_bgr[:, :, ch_idx]
        for bit_n in range(4):
            bit_plane = ((channel >> bit_n) & 1) * 255
            p = output_dir / f"lsb_{ch_name}_bit{bit_n}.png"
            cv2.imwrite(str(p), bit_plane)
            results["outputs"].append(str(p))

            if bit_n == 0:
                bp_entropy = _shannon_entropy(bit_plane)
                if bp_entropy > 7.0:
                    results["findings"].append(
                        f"ALERT: LSB (bit 0) of {ch_name} channel has "
                        f"entropy {bp_entropy:.3f} — possible steg content"
                    )

                ascii_text = _extract_lsb_ascii(channel)
                if ascii_text:
                    results["findings"].append(
                        f"LSB ASCII extraction ({ch_name}, row-major): "
                        f"found {len(ascii_text)} printable chars"
                    )
                    txt_path = output_dir / f"lsb_{ch_name}_ascii.txt"
                    txt_path.write_text(ascii_text, encoding="utf-8")
                    results["outputs"].append(str(txt_path))

    return results


def run_bitplane(
    image_path: Path, img_bgr: np.ndarray,
    img_gray: np.ndarray, output_dir: Path,
) -> dict[str, Any]:
    """Full 8-bit decomposition of each channel (32 planes total)."""
    results: dict[str, Any] = {
        "module": "bitplane", "findings": [], "outputs": [],
    }

    for ch_idx, ch_name in enumerate(["blue", "green", "red"]):
        channel = img_bgr[:, :, ch_idx]
        for bit_n in range(8):
            bit_plane = ((channel >> bit_n) & 1) * 255
            p = output_dir / f"bitplane_{ch_name}_bit{bit_n}.png"
            cv2.imwrite(str(p), bit_plane)
            results["outputs"].append(str(p))

    for bit_n in range(8):
        bit_plane = ((img_gray >> bit_n) & 1) * 255
        p = output_dir / f"bitplane_gray_bit{bit_n}.png"
        cv2.imwrite(str(p), bit_plane)
        results["outputs"].append(str(p))

    results["total_planes"] = 32
    return results


def run_ela(
    image_path: Path, img_bgr: np.ndarray,
    img_gray: np.ndarray, output_dir: Path,
) -> dict[str, Any]:
    """Error Level Analysis via JPEG recompression at multiple quality levels."""
    results: dict[str, Any] = {
        "module": "ela", "findings": [], "outputs": [],
    }

    is_jpeg = image_path.suffix.lower() in {".jpg", ".jpeg"}
    if not is_jpeg:
        results["findings"].append(
            "NOTE: ELA is less probative on non-JPEG originals; "
            "treat as a weak signal only."
        )

    for quality in [95, 90, 85, 75]:
        tmp_path = output_dir / f"_ela_tmp_q{quality}.jpg"
        cv2.imwrite(
            str(tmp_path), img_bgr,
            [cv2.IMWRITE_JPEG_QUALITY, quality],
        )
        recompressed = cv2.imread(str(tmp_path))
        tmp_path.unlink(missing_ok=True)

        if recompressed is None:
            results["findings"].append(
                f"ELA recompression failed at quality {quality}"
            )
            continue

        diff = cv2.absdiff(img_bgr, recompressed)
        ela_img = cv2.convertScaleAbs(diff, alpha=20, beta=0)

        ela_path = output_dir / f"ela_q{quality}.png"
        cv2.imwrite(str(ela_path), ela_img)
        results["outputs"].append(str(ela_path))

        mean_diff = float(np.mean(diff))
        max_diff = float(np.max(diff))
        std_diff = float(np.std(diff))

        results[f"q{quality}"] = {
            "mean_error": mean_diff,
            "max_error": max_diff,
            "std_error": std_diff,
        }

        gray_diff = cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY)
        thresh_val = int(mean_diff + 3 * std_diff)
        _, thresh = cv2.threshold(gray_diff, thresh_val, 255, cv2.THRESH_BINARY)
        hot_ratio = float(np.sum(thresh > 0)) / thresh.size
        if 0.001 < hot_ratio < 0.3:
            results["findings"].append(
                f"ALERT: ELA at Q{quality} shows {hot_ratio:.4%} localized "
                "hot pixels — possible compositing or selective editing"
            )

    return results


def run_fft(
    image_path: Path, img_bgr: np.ndarray,
    img_gray: np.ndarray, output_dir: Path,
) -> dict[str, Any]:
    """2D FFT frequency domain analysis for hidden periodic patterns."""
    results: dict[str, Any] = {
        "module": "fft", "findings": [], "outputs": [],
    }

    f_transform = np.fft.fft2(img_gray.astype(np.float64))
    f_shift = np.fft.fftshift(f_transform)

    # Log-magnitude spectrum
    magnitude = np.log1p(np.abs(f_shift))
    mag_norm = cv2.normalize(
        magnitude, None, 0, 255, cv2.NORM_MINMAX,
    ).astype(np.uint8)
    mag_path = output_dir / "fft_magnitude.png"
    cv2.imwrite(str(mag_path), mag_norm)
    results["outputs"].append(str(mag_path))

    # Phase spectrum
    phase = np.angle(f_shift)
    phase_norm = cv2.normalize(
        phase, None, 0, 255, cv2.NORM_MINMAX,
    ).astype(np.uint8)
    phase_path = output_dir / "fft_phase.png"
    cv2.imwrite(str(phase_path), phase_norm)
    results["outputs"].append(str(phase_path))

    # Detect anomalous peaks (mask out DC center)
    h, w = mag_norm.shape
    cy, cx = h // 2, w // 2
    mask_radius = min(h, w) // 20
    mag_masked = magnitude.copy()
    cv2.circle(mag_masked, (cx, cy), mask_radius, 0, -1)

    peak_threshold = np.mean(mag_masked) + 4 * np.std(mag_masked)
    peaks = np.argwhere(mag_masked > peak_threshold)

    if 0 < len(peaks) < 200:
        results["findings"].append(
            f"ALERT: {len(peaks)} anomalous frequency peaks detected — "
            "possible periodic hidden pattern or watermark"
        )
        results["peak_count"] = len(peaks)

        mag_color = cv2.cvtColor(mag_norm, cv2.COLOR_GRAY2BGR)
        for py, px in peaks:
            cv2.circle(mag_color, (px, py), 3, (0, 0, 255), 1)
        annotated_path = output_dir / "fft_magnitude_peaks.png"
        cv2.imwrite(str(annotated_path), mag_color)
        results["outputs"].append(str(annotated_path))

    # Directional band-pass: isolate horizontal and vertical frequency bands
    band_width = max(2, min(h, w) // 100)
    for direction, label in [("horizontal", "H"), ("vertical", "V")]:
        band = np.zeros_like(f_shift)
        if direction == "horizontal":
            band[cy - band_width:cy + band_width, :] = (
                f_shift[cy - band_width:cy + band_width, :]
            )
        else:
            band[:, cx - band_width:cx + band_width] = (
                f_shift[:, cx - band_width:cx + band_width]
            )
        reconstructed = np.abs(np.fft.ifft2(np.fft.ifftshift(band)))
        recon_norm = cv2.normalize(
            reconstructed, None, 0, 255, cv2.NORM_MINMAX,
        ).astype(np.uint8)
        p = output_dir / f"fft_band_{label}.png"
        cv2.imwrite(str(p), recon_norm)
        results["outputs"].append(str(p))

    return results


def run_chi_square(
    image_path: Path, img_bgr: np.ndarray,
    img_gray: np.ndarray, output_dir: Path,
) -> dict[str, Any]:
    """Chi-square steganalysis for LSB replacement detection."""
    results: dict[str, Any] = {
        "module": "chi_square", "findings": [], "outputs": [],
    }

    if not HAS_SCIPY:
        results["findings"].append(
            "scipy not installed — chi-square test skipped"
        )
        return results

    # Per-channel whole-image chi-square test
    for ch_idx, ch_name in enumerate(["blue", "green", "red"]):
        channel = img_bgr[:, :, ch_idx].flatten()
        hist = np.bincount(channel, minlength=256).astype(np.float64)

        chi_sq = 0.0
        dof = 0
        for k in range(128):
            v0, v1 = hist[2 * k], hist[2 * k + 1]
            expected = (v0 + v1) / 2.0
            if expected > 0:
                chi_sq += ((v0 - expected) ** 2 + (v1 - expected) ** 2) / expected
                dof += 1

        if dof > 0:
            p_value = 1.0 - scipy_chi2.cdf(chi_sq, dof)
            results[f"{ch_name}_chi_square"] = float(chi_sq)
            results[f"{ch_name}_p_value"] = float(p_value)
            results[f"{ch_name}_dof"] = dof

            if p_value < 0.05:
                results["findings"].append(
                    f"ALERT: {ch_name} channel chi-square p-value = "
                    f"{p_value:.6f} — statistically significant evidence "
                    "of LSB replacement steganography"
                )

    # Block-wise p-value heatmap for spatial localization
    block_size = 64
    h, w = img_gray.shape
    bh, bw = h // block_size, w // block_size
    if bh > 0 and bw > 0:
        p_map = np.ones((bh, bw), dtype=np.float64)
        for by in range(bh):
            for bx in range(bw):
                block = img_gray[
                    by * block_size:(by + 1) * block_size,
                    bx * block_size:(bx + 1) * block_size,
                ].flatten()
                hist_block = np.bincount(block, minlength=256).astype(np.float64)
                chi_sq_b, dof_b = 0.0, 0
                for k in range(128):
                    v0, v1 = hist_block[2 * k], hist_block[2 * k + 1]
                    exp = (v0 + v1) / 2.0
                    if exp > 5:
                        chi_sq_b += ((v0 - exp) ** 2 + (v1 - exp) ** 2) / exp
                        dof_b += 1
                if dof_b > 0:
                    p_map[by, bx] = 1.0 - scipy_chi2.cdf(chi_sq_b, dof_b)

        p_vis = (p_map * 255).astype(np.uint8)
        p_resized = cv2.resize(p_vis, (w, h), interpolation=cv2.INTER_NEAREST)
        p_color = cv2.applyColorMap(p_resized, cv2.COLORMAP_JET)
        pmap_path = output_dir / "chi_square_pvalue_map.png"
        cv2.imwrite(str(pmap_path), p_color)
        results["outputs"].append(str(pmap_path))

    return results


def run_noise_residual(
    image_path: Path, img_bgr: np.ndarray,
    img_gray: np.ndarray, output_dir: Path,
) -> dict[str, Any]:
    """Gaussian blur residual — highlights local texture inconsistency."""
    results: dict[str, Any] = {
        "module": "noise_residual", "findings": [], "outputs": [],
    }

    blurred = cv2.GaussianBlur(img_gray, (0, 0), sigmaX=2.0)
    residual = img_gray.astype(np.float32) - blurred.astype(np.float32)
    display = _normalize_u8(residual)

    p = output_dir / "noise_residual.png"
    cv2.imwrite(str(p), display)
    results["outputs"].append(str(p))

    results["mean_abs"] = float(np.mean(np.abs(residual)))
    results["std"] = float(np.std(residual))
    results["p95_abs"] = float(np.percentile(np.abs(residual), 95))

    # Check for spatially non-uniform noise (split into quadrants)
    h, w = residual.shape
    quads = [
        residual[:h // 2, :w // 2],
        residual[:h // 2, w // 2:],
        residual[h // 2:, :w // 2],
        residual[h // 2:, w // 2:],
    ]
    quad_stds = [float(np.std(q)) for q in quads]
    if max(quad_stds) > 2 * min(quad_stds) and min(quad_stds) > 0.5:
        results["findings"].append(
            f"ALERT: Noise residual is spatially non-uniform — "
            f"quadrant std range [{min(quad_stds):.2f}, {max(quad_stds):.2f}]. "
            "May indicate localized processing or compositing."
        )

    return results


def run_line_analysis(
    image_path: Path, img_bgr: np.ndarray,
    img_gray: np.ndarray, output_dir: Path,
) -> dict[str, Any]:
    """Hough line detection with dominant angle distribution."""
    results: dict[str, Any] = {
        "module": "line_analysis", "findings": [], "outputs": [],
    }

    edges = cv2.Canny(img_gray, 80, 180)
    overlay = img_bgr.copy()
    lines = cv2.HoughLinesP(
        edges, rho=1, theta=np.pi / 180, threshold=80,
        minLineLength=max(30, min(img_bgr.shape[:2]) // 8),
        maxLineGap=10,
    )

    angles = []
    count = 0
    if lines is not None:
        for line in lines[:500]:
            x1, y1, x2, y2 = line[0]
            cv2.line(overlay, (x1, y1), (x2, y2), (0, 255, 0), 1)
            angle = math.degrees(math.atan2(y2 - y1, x2 - x1))
            angle = ((angle + 90) % 180) - 90
            angles.append(round(angle, 1))
            count += 1

    p = output_dir / "lines_overlay.png"
    cv2.imwrite(str(p), overlay)
    results["outputs"].append(str(p))

    rounded = [int(round(a / 5.0) * 5) for a in angles]
    common = Counter(rounded).most_common(6)
    results["line_count"] = count
    results["dominant_angles_deg"] = [
        {"angle": a, "count": c} for a, c in common
    ]

    if count >= 20 and common:
        dominant = ", ".join(
            f"{a}deg ({c})" for a, c in common[:3]
        )
        results["findings"].append(
            f"Line analysis found strong linear structure ({count} lines). "
            f"Dominant angles: {dominant}."
        )

    return results


def run_clone_detection(
    image_path: Path, img_bgr: np.ndarray,
    img_gray: np.ndarray, output_dir: Path,
) -> dict[str, Any]:
    """Block-hash clone candidate screening for copy-move detection."""
    results: dict[str, Any] = {
        "module": "clone_detection", "findings": [], "outputs": [],
    }

    h, w = img_gray.shape[:2]
    block = 16 if min(h, w) >= 256 else 12
    stride = max(8, block // 2)
    min_var = 40.0
    groups: dict[str, list[tuple[int, int]]] = defaultdict(list)

    for y in range(0, h - block + 1, stride):
        for x in range(0, w - block + 1, stride):
            patch = img_gray[y:y + block, x:x + block]
            if float(np.var(patch)) < min_var:
                continue
            small = cv2.resize(patch, (8, 8), interpolation=cv2.INTER_AREA)
            sig = (small > np.mean(small)).astype(np.uint8).flatten()
            key = "".join(map(str, sig.tolist()))
            groups[key].append((x, y))

    candidate_pairs = []
    candidate_boxes: set[tuple[int, int]] = set()

    for positions in groups.values():
        if len(positions) < 2:
            continue
        limited = positions[:20]
        for i in range(len(limited)):
            for j in range(i + 1, len(limited)):
                x1, y1 = limited[i]
                x2, y2 = limited[j]
                if abs(x1 - x2) + abs(y1 - y2) < block * 2:
                    continue
                candidate_pairs.append(((x1, y1), (x2, y2)))
                candidate_boxes.add((x1, y1))
                candidate_boxes.add((x2, y2))
                if len(candidate_pairs) >= 50:
                    break
            if len(candidate_pairs) >= 50:
                break
        if len(candidate_pairs) >= 50:
            break

    overlay = cv2.cvtColor(img_gray, cv2.COLOR_GRAY2BGR)
    for (x, y) in list(candidate_boxes)[:80]:
        cv2.rectangle(overlay, (x, y), (x + block, y + block), (0, 0, 255), 1)

    p = output_dir / "clone_candidates.png"
    cv2.imwrite(str(p), overlay)
    results["outputs"].append(str(p))

    results["block_size"] = block
    results["candidate_pair_count"] = len(candidate_pairs)
    results["candidate_box_count"] = len(candidate_boxes)
    results["pairs"] = [
        {
            "a": {"x": int(a[0]), "y": int(a[1])},
            "b": {"x": int(b[0]), "y": int(b[1])},
        }
        for a, b in candidate_pairs[:20]
    ]

    if len(candidate_pairs) >= 3:
        results["findings"].append(
            f"Clone screening found {len(candidate_pairs)} non-local "
            "repeated patch candidates; treat as investigative leads only."
        )

    return results


def run_edge_contour(
    image_path: Path, img_bgr: np.ndarray,
    img_gray: np.ndarray, output_dir: Path,
) -> dict[str, Any]:
    """Multi-threshold edge detection + contour shape analysis."""
    results: dict[str, Any] = {
        "module": "edge_contour", "findings": [], "outputs": [],
    }

    for low, high, label in [(50, 150, "low"), (100, 200, "mid"),
                              (150, 300, "high")]:
        edges = cv2.Canny(img_gray, low, high)
        p = output_dir / f"edges_canny_{label}.png"
        cv2.imwrite(str(p), edges)
        results["outputs"].append(str(p))

    edges_mid = cv2.Canny(img_gray, 100, 200)
    contours, _ = cv2.findContours(
        edges_mid, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE,
    )

    results["contour_count"] = len(contours)

    contour_data = []
    overlay = img_bgr.copy()
    for i, cnt in enumerate(contours):
        area = cv2.contourArea(cnt)
        if area < 100:
            continue
        perimeter = cv2.arcLength(cnt, True)
        circularity = (
            (4 * np.pi * area / (perimeter ** 2)) if perimeter > 0 else 0
        )
        x, y, w, h = cv2.boundingRect(cnt)
        contour_data.append({
            "index": i,
            "area": float(area),
            "perimeter": float(perimeter),
            "circularity": float(circularity),
            "bounding_rect": {"x": int(x), "y": int(y), "w": int(w), "h": int(h)},
            "aspect_ratio": float(w / h) if h > 0 else 0,
        })
        cv2.drawContours(overlay, [cnt], -1, (0, 255, 0), 1)

    results["significant_contours"] = len(contour_data)

    overlay_path = output_dir / "contour_overlay.png"
    cv2.imwrite(str(overlay_path), overlay)
    results["outputs"].append(str(overlay_path))

    if len(contour_data) > 10:
        centroids = [
            (cd["bounding_rect"]["x"] + cd["bounding_rect"]["w"] / 2,
             cd["bounding_rect"]["y"] + cd["bounding_rect"]["h"] / 2)
            for cd in contour_data
        ]
        regularity = _check_grid_regularity(centroids)
        if regularity["is_regular"]:
            results["findings"].append(
                f"ALERT: Contour centroids show grid-like regularity — "
                f"estimated spacing: {regularity['spacing']:.1f}px"
            )
        results["grid_regularity"] = regularity

    return results


def run_ocr(
    image_path: Path, img_bgr: np.ndarray,
    img_gray: np.ndarray, output_dir: Path,
) -> dict[str, Any]:
    """OCR text extraction with multiple preprocessing variants."""
    results: dict[str, Any] = {
        "module": "ocr", "findings": [], "outputs": [],
    }

    if not HAS_TESSERACT:
        results["findings"].append(
            "pytesseract not installed — OCR skipped. "
            "Install: pip install pytesseract && apt install tesseract-ocr"
        )
        return results

    variants = {
        "original": img_gray,
        "threshold_binary": cv2.threshold(
            img_gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU,
        )[1],
        "threshold_inv": cv2.threshold(
            img_gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU,
        )[1],
        "contrast_enhanced": cv2.equalizeHist(img_gray),
    }

    all_text = {}
    for variant_name, variant_img in variants.items():
        try:
            text = pytesseract.image_to_string(variant_img).strip()
            if text:
                all_text[variant_name] = text
                txt_path = output_dir / f"ocr_{variant_name}.txt"
                txt_path.write_text(text, encoding="utf-8")
                results["outputs"].append(str(txt_path))
        except Exception as exc:
            results["findings"].append(f"OCR ({variant_name}) failed: {exc}")

    if all_text:
        best_variant = max(all_text, key=lambda k: len(all_text[k]))
        results["best_variant"] = best_variant
        results["extracted_text_length"] = len(all_text[best_variant])
        results["findings"].append(
            f"OCR extracted {len(all_text[best_variant])} characters "
            f"(best variant: {best_variant})"
        )
    else:
        results["findings"].append(
            "No text detected in any preprocessing variant."
        )

    return results


# ---------------------------------------------------------------------------
# Module registry
# ---------------------------------------------------------------------------

AVAILABLE_MODULES = [
    "metadata", "statistical", "channel", "lsb", "bitplane",
    "ela", "fft", "chi_square", "noise_residual", "line_analysis",
    "clone_detection", "edge_contour", "ocr",
]

MODULE_FUNCTIONS = {
    "metadata": run_metadata,
    "statistical": run_statistical,
    "channel": run_channel,
    "lsb": run_lsb,
    "bitplane": run_bitplane,
    "ela": run_ela,
    "fft": run_fft,
    "chi_square": run_chi_square,
    "noise_residual": run_noise_residual,
    "line_analysis": run_line_analysis,
    "clone_detection": run_clone_detection,
    "edge_contour": run_edge_contour,
    "ocr": run_ocr,
}


# ===================================================================
#  ANALYZE — Single-image forensic pipeline
# ===================================================================

def analyze_image(
    image_path: str,
    output_dir: str = "./results/forensic",
    modules: list[str] | None = None,
) -> dict[str, Any]:
    """Run the forensic analysis pipeline on a single image.

    Args:
        image_path: Path to the input image file.
        output_dir: Directory for output artifacts.
        modules: Module IDs to run (default: all).

    Returns:
        Structured report dict with results from all requested modules.
    """
    path = Path(image_path)
    if not path.exists():
        raise FileNotFoundError(f"Image not found: {image_path}")
    if path.suffix.lower() not in SUPPORTED_EXTS:
        raise ValueError(f"Unsupported format: {path.suffix}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    img_bgr = cv2.imread(str(path))
    if img_bgr is None:
        raise ValueError(f"Cannot decode image: {image_path}")
    img_gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)

    if modules is None:
        modules = list(AVAILABLE_MODULES)
    else:
        invalid = [m for m in modules if m not in MODULE_FUNCTIONS]
        if invalid:
            raise ValueError(
                f"Unknown modules: {invalid}. "
                f"Available: {AVAILABLE_MODULES}"
            )

    report: dict[str, Any] = {
        "image": str(path.resolve()),
        "dimensions": {
            "height": img_bgr.shape[0],
            "width": img_bgr.shape[1],
            "channels": img_bgr.shape[2],
        },
        "file_size_bytes": path.stat().st_size,
        "modules_run": modules,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "results": {},
        "anomaly_summary": [],
    }

    for mod_name in modules:
        print(f"  [*] Running module: {mod_name}...")
        try:
            result = MODULE_FUNCTIONS[mod_name](path, img_bgr, img_gray, out)
            report["results"][mod_name] = result
            for finding in result.get("findings", []):
                if "ALERT" in finding:
                    report["anomaly_summary"].append(finding)
        except Exception as exc:
            report["results"][mod_name] = {
                "module": mod_name, "error": str(exc),
            }
            print(f"  [!] Module {mod_name} failed: {exc}")

    report_path = out / "forensic_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    summary_path = out / "SUMMARY.md"
    _write_analysis_summary(report, summary_path)

    print(f"\n  Report: {report_path}")
    print(f"  Summary: {summary_path}")

    return report


def _write_analysis_summary(report: dict[str, Any], path: Path) -> None:
    """Generate a human-readable markdown summary of the forensic report."""
    lines = [
        "# Forensic Photo Analysis — Summary",
        "",
        f"**Image:** `{report['image']}`  ",
        f"**Dimensions:** {report['dimensions']['width']}"
        f" x {report['dimensions']['height']}  ",
        f"**File size:** {report['file_size_bytes']:,} bytes  ",
        f"**Timestamp:** {report['timestamp']}  ",
        f"**Modules:** {', '.join(report['modules_run'])}",
        "",
    ]

    anomalies = report.get("anomaly_summary", [])
    if anomalies:
        lines.append("## Anomalies Detected")
        lines.append("")
        for a in anomalies:
            lines.append(f"- {a}")
        lines.append("")
    else:
        lines.append("## No Anomalies Detected")
        lines.append("")
        lines.append(
            "All modules completed without flagging statistical anomalies."
        )
        lines.append("")

    lines.append("## Module Results")
    lines.append("")
    for mod_name in report.get("modules_run", []):
        mod_result = report["results"].get(mod_name, {})
        lines.append(f"### {mod_name}")
        if "error" in mod_result:
            lines.append(f"**Error:** {mod_result['error']}")
        else:
            findings = mod_result.get("findings", [])
            if findings:
                for f_item in findings:
                    lines.append(f"- {f_item}")
            else:
                lines.append("- No findings.")
            outputs = mod_result.get("outputs", [])
            if outputs:
                lines.append(f"- Output files: {len(outputs)}")
        lines.append("")

    lines += [
        "## Interpretation Guidance",
        "",
        "- Do not claim manipulation from a single indicator.",
        "- Prefer at least two corroborating indicators before asserting "
        "a localized anomaly.",
        "- Compression, rescanning, glare, and sharpening can mimic "
        "tampering artifacts.",
        "- Clone candidates and ELA hotspots require visual corroboration.",
        "",
        "## Confidence Assessment",
        "",
    ]

    # Auto-assess confidence based on image quality
    stat_results = report["results"].get("statistical", {})
    sharpness = stat_results.get("sharpness_laplacian_var", 0)
    edge_dens = stat_results.get("edge_density", 0)
    if sharpness < 40:
        lines.append("- **Low** — Image is soft/blurred, limiting "
                      "forensic reliability.")
    elif sharpness > 120 and edge_dens > 0.04:
        lines.append("- **Medium to High** — Image is sharp with good "
                      "structural detail.")
    else:
        lines.append("- **Medium** — Acceptable for screening but not "
                      "for conclusive determination.")

    lines.append("")
    lines.append("---")
    lines.append("*Generated by forensic_photo_analyzer.py*")

    path.write_text("\n".join(lines), encoding="utf-8")


# ===================================================================
#  COMPARE — Two-image alignment and difference analysis
# ===================================================================

def compare_images(
    reference_path: str,
    candidate_path: str,
    output_dir: str = "./comparison_output",
) -> dict[str, Any]:
    """Align two photos of the same subject and produce difference products.

    Uses ORB feature matching + RANSAC homography for alignment, then
    generates a difference map and annotated overlay.

    Args:
        reference_path: Path to the reference image.
        candidate_path: Path to the candidate (compared) image.
        output_dir: Directory for output artifacts.

    Returns:
        Structured comparison report dict.
    """
    ref_path = Path(reference_path)
    cand_path = Path(candidate_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ref_bgr = cv2.imread(str(ref_path))
    cand_bgr = cv2.imread(str(cand_path))
    if ref_bgr is None:
        raise FileNotFoundError(f"Cannot load reference: {reference_path}")
    if cand_bgr is None:
        raise FileNotFoundError(f"Cannot load candidate: {candidate_path}")

    # ORB feature matching for alignment
    ref_gray = cv2.cvtColor(ref_bgr, cv2.COLOR_BGR2GRAY)
    cand_gray = cv2.cvtColor(cand_bgr, cv2.COLOR_BGR2GRAY)

    orb = cv2.ORB_create(nfeatures=3000)
    kp1, des1 = orb.detectAndCompute(ref_gray, None)
    kp2, des2 = orb.detectAndCompute(cand_gray, None)

    if des1 is None or des2 is None or len(kp1) < 8 or len(kp2) < 8:
        raise RuntimeError("Not enough keypoints to align images.")

    matcher = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = sorted(matcher.match(des1, des2), key=lambda m: m.distance)
    good = matches[:min(300, len(matches))]

    if len(good) < 8:
        raise RuntimeError("Not enough reliable matches to align images.")

    src = np.float32([kp2[m.trainIdx].pt for m in good]).reshape(-1, 1, 2)
    dst = np.float32([kp1[m.queryIdx].pt for m in good]).reshape(-1, 1, 2)
    H, mask = cv2.findHomography(src, dst, cv2.RANSAC, 5.0)

    if H is None:
        raise RuntimeError("Homography estimation failed.")

    aligned = cv2.warpPerspective(
        cand_bgr, H, (ref_bgr.shape[1], ref_bgr.shape[0]),
    )
    inliers = int(mask.ravel().sum()) if mask is not None else 0

    # Difference products
    diff = cv2.absdiff(ref_bgr, aligned)
    diff_gray = cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY)
    diff_map = _normalize_u8(diff_gray)

    _, thresh = cv2.threshold(diff_gray, 25, 255, cv2.THRESH_BINARY)
    kernel = np.ones((3, 3), np.uint8)
    thresh = cv2.morphologyEx(thresh, cv2.MORPH_OPEN, kernel)
    thresh = cv2.dilate(thresh, kernel, iterations=1)

    overlay = ref_bgr.copy()
    contours, _ = cv2.findContours(
        thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE,
    )
    boxes = []
    for c in contours:
        area = cv2.contourArea(c)
        if area < 50:
            continue
        x, y, w, h = cv2.boundingRect(c)
        cv2.rectangle(overlay, (x, y), (x + w, y + h), (0, 0, 255), 1)
        boxes.append({
            "x": int(x), "y": int(y), "w": int(w), "h": int(h),
            "area": float(area),
        })

    cv2.imwrite(str(out / "aligned_candidate.png"), aligned)
    cv2.imwrite(str(out / "difference_map.png"), diff_map)
    cv2.imwrite(str(out / "difference_overlay.png"), overlay)

    report = {
        "reference": str(ref_path.resolve()),
        "candidate": str(cand_path.resolve()),
        "alignment": {
            "keypoints_reference": len(kp1),
            "keypoints_candidate": len(kp2),
            "match_count": len(matches),
            "used_match_count": len(good),
            "homography_inliers": inliers,
        },
        "difference": {
            "mean_abs_diff": float(np.mean(diff_gray)),
            "p95_abs_diff": float(np.percentile(diff_gray, 95)),
            "changed_pixel_fraction": float(np.mean(thresh > 0)),
            "changed_region_count": len(boxes),
            "boxes": boxes[:50],
        },
    }

    (out / "comparison_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8",
    )

    # Summary
    summary_lines = [
        "# Image Comparison Summary",
        "",
        f"**Reference:** `{report['reference']}`  ",
        f"**Candidate:** `{report['candidate']}`  ",
        "",
        "## Alignment",
        f"- Used {report['alignment']['used_match_count']} keypoint "
        f"matches with {report['alignment']['homography_inliers']} inliers.",
        "",
        "## Differences",
        f"- Mean absolute difference: "
        f"{report['difference']['mean_abs_diff']:.2f}",
        f"- Changed-pixel fraction: "
        f"{report['difference']['changed_pixel_fraction']:.2%}",
        f"- Changed regions: "
        f"{report['difference']['changed_region_count']}",
        "",
        "## Interpretation",
        "- Post-alignment differences can reflect true scene change, "
        "lighting shift, perspective mismatch, focus difference, glare, "
        "or compression differences.",
        "- Treat highlighted boxes as areas to inspect, not proof of "
        "alteration.",
        "",
        "## Limitations",
        "- Large viewpoint differences reduce alignment quality.",
        "- Reflective surfaces and shadows can dominate the difference map.",
        "",
        "---",
        "*Generated by forensic_photo_analyzer.py*",
    ]
    (out / "comparison_summary.md").write_text(
        "\n".join(summary_lines), encoding="utf-8",
    )

    print(f"  Comparison report: {out / 'comparison_report.json'}")
    print(f"  Comparison summary: {out / 'comparison_summary.md'}")

    return report


# ===================================================================
#  CORRECT — Perspective correction
# ===================================================================

def correct_perspective(
    image_path: str,
    corners: Sequence[tuple[int, int]] | None = None,
    output_width: int | None = None,
    output_height: int | None = None,
) -> np.ndarray:
    """Apply perspective correction to rectify an angled photograph.

    Args:
        image_path: Path to the input image.
        corners: Four (x, y) tuples: TL, TR, BR, BL. If None, attempts
                 automatic quadrilateral detection.
        output_width: Width of corrected output (estimated if None).
        output_height: Height of corrected output (estimated if None).

    Returns:
        Perspective-corrected image as BGR numpy array.
    """
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Cannot load image: {image_path}")

    if corners is None:
        corners = _auto_detect_quad(img)
        if corners is None:
            raise ValueError(
                "Automatic quadrilateral detection failed. "
                "Please provide corner coordinates manually."
            )

    if len(corners) != 4:
        raise ValueError(f"Expected 4 corners, got {len(corners)}")

    src_pts = np.array(corners, dtype=np.float32)

    if output_width is None:
        w1 = np.linalg.norm(src_pts[1] - src_pts[0])
        w2 = np.linalg.norm(src_pts[2] - src_pts[3])
        output_width = int(max(w1, w2))
    if output_height is None:
        h1 = np.linalg.norm(src_pts[3] - src_pts[0])
        h2 = np.linalg.norm(src_pts[2] - src_pts[1])
        output_height = int(max(h1, h2))

    dst_pts = np.array([
        [0, 0],
        [output_width - 1, 0],
        [output_width - 1, output_height - 1],
        [0, output_height - 1],
    ], dtype=np.float32)

    matrix = cv2.getPerspectiveTransform(src_pts, dst_pts)
    return cv2.warpPerspective(img, matrix, (output_width, output_height))


def _auto_detect_quad(img: np.ndarray) -> list[tuple[int, int]] | None:
    """Detect the largest quadrilateral via edge detection + contour approx."""
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    edges = cv2.Canny(blurred, 50, 150)

    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
    edges = cv2.dilate(edges, kernel, iterations=2)

    contours, _ = cv2.findContours(
        edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE,
    )
    if not contours:
        return None

    contours = sorted(contours, key=cv2.contourArea, reverse=True)
    for cnt in contours[:10]:
        peri = cv2.arcLength(cnt, True)
        approx = cv2.approxPolyDP(cnt, 0.02 * peri, True)
        if len(approx) == 4:
            pts = approx.reshape(4, 2)
            return _order_corners(pts)

    return None


def _order_corners(pts: np.ndarray) -> list[tuple[int, int]]:
    """Order four points as: TL, TR, BR, BL."""
    s = pts.sum(axis=1)
    d = np.diff(pts, axis=1).flatten()

    tl = pts[np.argmin(s)]
    br = pts[np.argmax(s)]
    tr = pts[np.argmin(d)]
    bl = pts[np.argmax(d)]

    return [
        (int(tl[0]), int(tl[1])),
        (int(tr[0]), int(tr[1])),
        (int(br[0]), int(br[1])),
        (int(bl[0]), int(bl[1])),
    ]


# ===================================================================
#  CLI
# ===================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Comprehensive Forensic Photo Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s analyze photo.jpg -o ./output\n"
            "  %(prog)s analyze photo.jpg -m ela,fft,chi_square\n"
            "  %(prog)s compare ref.jpg candidate.jpg -o ./cmp_output\n"
            "  %(prog)s correct angled.jpg --auto -o corrected.jpg\n"
            "  %(prog)s correct angled.jpg -c 100,50 900,60 880,700 110,710\n"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # --- analyze ---
    p_analyze = subparsers.add_parser(
        "analyze", help="Run forensic analysis pipeline on a single image",
    )
    p_analyze.add_argument("image", help="Path to the image file")
    p_analyze.add_argument(
        "-o", "--output-dir", default="./results/forensic",
        help="Directory for output artifacts (default: ./results/forensic)",
    )
    p_analyze.add_argument(
        "-m", "--modules", default=None,
        help=(
            f"Comma-separated module list (default: all). "
            f"Available: {','.join(AVAILABLE_MODULES)}"
        ),
    )

    # --- compare ---
    p_compare = subparsers.add_parser(
        "compare", help="Align and diff two images of the same subject",
    )
    p_compare.add_argument("reference", help="Reference image path")
    p_compare.add_argument("candidate", help="Candidate image path")
    p_compare.add_argument(
        "-o", "--output-dir", default="./comparison_output",
        help="Directory for output artifacts",
    )

    # --- correct ---
    p_correct = subparsers.add_parser(
        "correct", help="Apply perspective correction to an angled photo",
    )
    p_correct.add_argument("image", help="Path to the input image")
    p_correct.add_argument(
        "-c", "--corners", nargs=4, metavar="X,Y",
        help="Four corner coordinates as X,Y pairs (TL TR BR BL)",
    )
    p_correct.add_argument(
        "--auto", action="store_true",
        help="Attempt automatic quadrilateral detection",
    )
    p_correct.add_argument(
        "-o", "--output", default=None,
        help="Output path (default: <input>_corrected.<ext>)",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "analyze":
        modules = args.modules.split(",") if args.modules else None
        print("Forensic Photo Analysis Pipeline")
        print("=" * 40)
        print(f"Image:   {args.image}")
        print(f"Output:  {args.output_dir}")
        print(f"Modules: {modules or 'ALL'}")
        print()
        report = analyze_image(args.image, args.output_dir, modules)
        anomalies = report.get("anomaly_summary", [])
        print(f"\n{'=' * 40}")
        print(f"Done. {len(anomalies)} anomalies detected.")
        for a in anomalies:
            print(f"  >> {a}")

    elif args.command == "compare":
        print("Forensic Image Comparison")
        print("=" * 40)
        print(f"Reference: {args.reference}")
        print(f"Candidate: {args.candidate}")
        print(f"Output:    {args.output_dir}")
        print()
        compare_images(args.reference, args.candidate, args.output_dir)

    elif args.command == "correct":
        corners = None
        if args.corners:
            corners = []
            for coord in args.corners:
                x, y = coord.split(",")
                corners.append((int(x), int(y)))
        elif not args.auto:
            print("Error: provide --corners or --auto", file=sys.stderr)
            sys.exit(1)

        output = args.output
        if output is None:
            p = Path(args.image)
            output = str(p.parent / f"{p.stem}_corrected{p.suffix}")

        corrected = correct_perspective(args.image, corners)
        cv2.imwrite(output, corrected)
        print(f"Corrected image saved to: {output}")


if __name__ == "__main__":
    main()
