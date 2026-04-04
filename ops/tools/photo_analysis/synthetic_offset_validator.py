#!/usr/bin/env python3
"""
Synthetic Offset-Transfer Validator.

Generates controlled mock offset-transfer images from known text,
degrades them with realistic artifacts, then tests whether the
offset_transfer_analyzer pipeline can recover the faint marks.

This calibrates sensitivity and false-positive behavior.

Usage:
    python synthetic_offset_validator.py -o output/synthetic_validation/
"""

import json
import os
import sys
import time

import cv2
import numpy as np

# Import the analyzer we're validating
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from offset_transfer_analyzer import (
    run_enhancement_stack, detect_candidate_regions, classify_page,
    enhance_clahe, enhance_highpass, enhance_retinex,
)


def generate_blank_page(width: int = 985, height: int = 1300,
                        paper_color: int = 230,
                        noise_std: float = 5.0) -> np.ndarray:
    """Generate a synthetic blank page with realistic paper texture."""
    # Base paper color with slight variation
    page = np.full((height, width, 3), paper_color, dtype=np.uint8)

    # Add Gaussian noise for paper texture
    noise = np.random.normal(0, noise_std, page.shape).astype(np.float32)
    page = np.clip(page.astype(np.float32) + noise, 0, 255).astype(np.uint8)

    # Add subtle horizontal lines (lined notebook simulation)
    for y in range(50, height - 20, 30):
        # Faint blue line
        page[y:y+1, 20:width-20, 0] = np.clip(
            page[y:y+1, 20:width-20, 0].astype(np.float32) - 15, 0, 255
        ).astype(np.uint8)

    return page


def render_text_on_page(page: np.ndarray, text: str,
                        position: tuple = (100, 200),
                        font_scale: float = 1.2,
                        color: tuple = (30, 30, 30),
                        thickness: int = 2) -> np.ndarray:
    """Render text onto a page image."""
    result = page.copy()
    y = position[1]
    for line in text.split('\n'):
        cv2.putText(result, line.strip(), (position[0], y),
                    cv2.FONT_HERSHEY_SIMPLEX, font_scale, color, thickness)
        y += int(40 * font_scale)
    return result


def simulate_offset_transfer(source_page: np.ndarray,
                              opacity: float = 0.05,
                              blur_sigma: int = 3) -> np.ndarray:
    """Simulate ink offset transfer from a source page.

    Creates a faint, slightly blurred, horizontally mirrored impression
    of the source page's dark marks.

    opacity: how much of the source ink transfers (0.01 = very faint, 0.1 = visible)
    blur_sigma: how much the transferred ink spreads
    """
    gray = cv2.cvtColor(source_page, cv2.COLOR_BGR2GRAY)

    # Extract only the dark marks (ink)
    # Threshold to isolate ink
    _, ink_mask = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY_INV)

    # Mirror horizontally (contact transfer)
    mirrored = cv2.flip(ink_mask, 1)

    # Blur to simulate ink spread
    if blur_sigma > 0:
        ksize = blur_sigma * 2 + 1
        mirrored = cv2.GaussianBlur(mirrored, (ksize, ksize), 0)

    return mirrored, opacity


def apply_transfer_to_page(blank_page: np.ndarray,
                            transfer_mask: np.ndarray,
                            opacity: float) -> np.ndarray:
    """Apply a transfer mask to a blank page.

    Darkens the page where the transfer mask has ink,
    scaled by opacity.
    """
    result = blank_page.copy().astype(np.float32)

    # Resize mask if needed
    if transfer_mask.shape[:2] != blank_page.shape[:2]:
        transfer_mask = cv2.resize(transfer_mask,
                                    (blank_page.shape[1], blank_page.shape[0]))

    # Apply as darkening
    mask_f = transfer_mask.astype(np.float32) / 255.0
    for c in range(3):
        result[:, :, c] -= mask_f * opacity * 255

    return np.clip(result, 0, 255).astype(np.uint8)


def add_jpeg_artifacts(img: np.ndarray, quality: int = 85) -> np.ndarray:
    """Add JPEG compression artifacts."""
    _, encoded = cv2.imencode('.jpg', img, [cv2.IMWRITE_JPEG_QUALITY, quality])
    return cv2.imdecode(encoded, cv2.IMREAD_COLOR)


def add_illumination_gradient(img: np.ndarray, strength: float = 30) -> np.ndarray:
    """Add a diagonal illumination gradient (simulating uneven lighting)."""
    h, w = img.shape[:2]
    gradient = np.zeros((h, w), dtype=np.float32)
    for y in range(h):
        for x in range(w):
            gradient[y, x] = (x / w + y / h) * strength - strength / 2
    result = img.astype(np.float32)
    for c in range(3):
        result[:, :, c] += gradient
    return np.clip(result, 0, 255).astype(np.uint8)


def run_validation(output_dir: str) -> dict:
    """Run the full synthetic validation suite."""
    os.makedirs(output_dir, exist_ok=True)

    # Test text
    test_text = "SHADOW IN THE\nDARKNESS OF\nMIDNIGHT"

    # Generate source page with text
    source = generate_blank_page()
    source_with_text = render_text_on_page(source, test_text)

    cv2.imwrite(os.path.join(output_dir, "source_page.png"), source_with_text)

    # Test at different opacity levels
    opacities = [0.15, 0.10, 0.05, 0.03, 0.01]
    results = []

    for opacity in opacities:
        test_dir = os.path.join(output_dir, f"opacity_{opacity:.2f}")
        os.makedirs(test_dir, exist_ok=True)

        # Generate transfer
        transfer_mask, _ = simulate_offset_transfer(source_with_text, opacity)
        blank = generate_blank_page()
        transferred = apply_transfer_to_page(blank, transfer_mask, opacity)

        # Add realistic degradation
        transferred = add_illumination_gradient(transferred, strength=20)
        transferred = add_jpeg_artifacts(transferred, quality=85)

        cv2.imwrite(os.path.join(test_dir, "transferred_page.png"), transferred)
        cv2.imwrite(os.path.join(test_dir, "transfer_mask.png"), transfer_mask)

        # Classify
        cls, ink_density, mean_lum, std_lum = classify_page(transferred)

        # Run enhancement stack
        enhanced = run_enhancement_stack(transferred)

        # Save key enhancements
        for name in ["clahe_strong", "highpass_51", "retinex", "inverted"]:
            if name in enhanced:
                cv2.imwrite(os.path.join(test_dir, f"enhanced_{name}.png"),
                            enhanced[name])

        # Detect candidates across transforms
        detection_counts = {}
        total_candidates = 0
        for name, arr in enhanced.items():
            candidates = detect_candidate_regions(arr, min_area=30)
            detection_counts[name] = len(candidates)
            total_candidates += len(candidates)

        # Ground truth: the transfer mask has known regions
        gt_mask = (transfer_mask > 10).astype(np.uint8) * 255
        gt_contours, _ = cv2.findContours(gt_mask, cv2.RETR_EXTERNAL,
                                           cv2.CHAIN_APPROX_SIMPLE)
        gt_regions = len(gt_contours)

        result = {
            "opacity": opacity,
            "classification": cls,
            "ink_density": ink_density,
            "ground_truth_regions": gt_regions,
            "total_candidate_detections": total_candidates,
            "best_transforms": sorted(
                detection_counts.items(), key=lambda x: x[1], reverse=True
            )[:5],
            "detected": total_candidates > 0,
        }
        results.append(result)

        print(f"  Opacity {opacity:.2f}: class={cls}, ink={ink_density:.4f}, "
              f"GT={gt_regions} regions, detected={total_candidates} candidates")

    # Summary
    summary = {
        "test_text": test_text,
        "opacities_tested": opacities,
        "results": results,
        "sensitivity_curve": [
            {"opacity": r["opacity"], "detected": r["detected"],
             "candidates": r["total_candidate_detections"]}
            for r in results
        ],
        "minimum_detectable_opacity": min(
            (r["opacity"] for r in results if r["detected"]),
            default=None
        ),
        "false_negative_opacities": [
            r["opacity"] for r in results if not r["detected"]
        ],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    with open(os.path.join(output_dir, "validation_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    return summary


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Synthetic offset-transfer validation"
    )
    parser.add_argument("-o", "--output", required=True,
                        help="Output directory")
    args = parser.parse_args()

    print("=" * 60)
    print("Synthetic Offset-Transfer Validation")
    print("=" * 60)

    summary = run_validation(args.output)

    print(f"\nMinimum detectable opacity: {summary['minimum_detectable_opacity']}")
    print(f"False negatives at: {summary['false_negative_opacities']}")
    print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
