#!/usr/bin/env python3
"""Generate zoomed, high-contrast crops of each compass rose with degree overlay.

Produces three separate images, one per compass, cropped and enhanced for
angle measurement.
"""

import math
import os
import sys

from PIL import Image, ImageDraw, ImageFont, ImageEnhance, ImageFilter

INPUT = "ops/site_builder/static/archive/IMG_1518.jpg"
OUTDIR = "reference/Pictures"

img_orig = Image.open(INPUT)
W, H = img_orig.size

try:
    font_sm = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 18)
    font_md = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 22)
    font_lg = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 28)
except:
    font_sm = ImageFont.load_default()
    font_md = font_sm
    font_lg = font_sm

COMPASSES = [
    {"name": "A", "label": "Compass A (top-left)", "cx": 390, "cy": 350, "r": 205},
    {"name": "B", "label": "Compass B (top-right)", "cx": 1130, "cy": 330, "r": 215},
    {"name": "C", "label": "Compass C (bottom)", "cx": 750, "cy": 790, "r": 210},
]

for comp in COMPASSES:
    cx, cy, r = comp["cx"], comp["cy"], comp["r"]
    margin = 120

    # Crop region
    x1 = max(0, cx - r - margin)
    y1 = max(0, cy - r - margin)
    x2 = min(W, cx + r + margin)
    y2 = min(H, cy + r + margin)

    crop = img_orig.crop((x1, y1, x2, y2))

    # Enhance contrast
    enhancer = ImageEnhance.Contrast(crop)
    crop = enhancer.enhance(1.5)
    enhancer = ImageEnhance.Sharpness(crop)
    crop = enhancer.enhance(1.3)

    # Scale up 2x for better visibility
    scale = 2
    crop = crop.resize((crop.width * scale, crop.height * scale), Image.LANCZOS)

    # Adjusted center in cropped/scaled coordinates
    lcx = (cx - x1) * scale
    lcy = (cy - y1) * scale
    lr = r * scale

    draw = ImageDraw.Draw(crop)

    # Draw degree ring
    ring_r = lr + 12

    # Outer reference circle
    draw.ellipse([(lcx - ring_r, lcy - ring_r), (lcx + ring_r, lcy + ring_r)],
                 outline=(255, 80, 80), width=2)

    # Inner reference circle (at original drawn circle radius)
    draw.ellipse([(lcx - lr, lcy - lr), (lcx + lr, lcy + lr)],
                 outline=(255, 80, 80, 128), width=1)

    for deg in range(0, 360):
        rad = math.radians(deg - 90)

        if deg % 5 != 0:
            continue

        # Tick sizes
        if deg % 45 == 0:
            ti, to, tw = ring_r - 10, ring_r + 28, 3
        elif deg % 15 == 0:
            ti, to, tw = ring_r - 5, ring_r + 20, 2
        elif deg % 5 == 0:
            ti, to, tw = ring_r, ring_r + 12, 1

        xi = lcx + ti * math.cos(rad)
        yi = lcy + ti * math.sin(rad)
        xo = lcx + to * math.cos(rad)
        yo = lcy + to * math.sin(rad)

        color = (255, 50, 50) if deg % 45 == 0 else (200, 80, 80)
        draw.line([(xi, yi), (xo, yo)], fill=color, width=tw)

        # Labels every 15 degrees
        if deg % 15 == 0:
            label_r = ring_r + 38
            lx = lcx + label_r * math.cos(rad)
            ly = lcy + label_r * math.sin(rad)
            text = str(deg)
            f = font_md if deg % 45 == 0 else font_sm
            bbox = draw.textbbox((0, 0), text, font=f)
            tw2 = bbox[2] - bbox[0]
            th2 = bbox[3] - bbox[1]
            # Background for readability
            pad = 2
            draw.rectangle([(lx - tw2/2 - pad, ly - th2/2 - pad),
                           (lx + tw2/2 + pad, ly + th2/2 + pad)],
                          fill=(255, 255, 255, 200))
            draw.text((lx - tw2/2, ly - th2/2), text, fill=(200, 0, 0), font=f)

    # Cardinal labels with white background
    cardinals = [(0, "N"), (90, "E"), (180, "S"), (270, "W")]
    for deg, label in cardinals:
        rad = math.radians(deg - 90)
        lr2 = ring_r + 65
        lx = lcx + lr2 * math.cos(rad)
        ly = lcy + lr2 * math.sin(rad)
        bbox = draw.textbbox((0, 0), label, font=font_lg)
        tw2 = bbox[2] - bbox[0]
        th2 = bbox[3] - bbox[1]
        pad = 4
        draw.rectangle([(lx - tw2/2 - pad, ly - th2/2 - pad),
                       (lx + tw2/2 + pad, ly + th2/2 + pad)],
                      fill=(255, 255, 255))
        draw.text((lx - tw2/2, ly - th2/2), label, fill=(0, 0, 0), font=font_lg)

    # Crosshair at center
    ch = 15
    draw.line([(lcx - ch, lcy), (lcx + ch, lcy)], fill=(255, 0, 0), width=2)
    draw.line([(lcx, lcy - ch), (lcx, lcy + ch)], fill=(255, 0, 0), width=2)

    # Radial guide lines at key bearings for reference
    for guide_deg, guide_color, guide_label in [
        (67.5, (0, 200, 0), "67.5 (ENE)"),
        (247.5, (0, 200, 0), "247.5 (WSW)"),
    ]:
        rad = math.radians(guide_deg - 90)
        gx1 = lcx + (lr * 0.15) * math.cos(rad)
        gy1 = lcy + (lr * 0.15) * math.sin(rad)
        gx2 = lcx + (lr * 0.95) * math.cos(rad)
        gy2 = lcy + (lr * 0.95) * math.sin(rad)
        draw.line([(gx1, gy1), (gx2, gy2)], fill=guide_color, width=1)

    # Title
    draw.text((10, 10), comp["label"], fill=(200, 0, 0), font=font_lg)
    draw.text((10, 45), "Green lines = 67.5/247.5 (ENE/WSW) reference",
              fill=(0, 150, 0), font=font_sm)

    outpath = os.path.join(OUTDIR, f"compass_rose_{comp['name']}_zoom.png")
    crop.save(outpath, quality=95)
    print(f"Saved: {outpath} ({crop.width}x{crop.height})")

print("\nDone. Open with:")
for comp in COMPASSES:
    print(f"  reference/Pictures/compass_rose_{comp['name']}_zoom.png")
