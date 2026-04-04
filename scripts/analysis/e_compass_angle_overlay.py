#!/usr/bin/env python3
"""Overlay 360-degree markers on the three compass roses from IMG_1518.

Reads the archive photo of Sanborn's three hand-drawn compass roses on
graph paper and overlays graduated degree markers (every 5 degrees, labeled
every 15 degrees) on each circle to enable precise angle measurement of
the needle directions.

Output: reference/Pictures/compass_roses_annotated.jpg
"""

import math
import sys
import os

# Use venv for PIL
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from PIL import Image, ImageDraw, ImageFont

INPUT = "ops/site_builder/static/archive/IMG_1518.jpg"
OUTPUT = "reference/Pictures/compass_roses_annotated.png"

img = Image.open(INPUT)
draw = ImageDraw.Draw(img)
W, H = img.size
print(f"Image: {W}x{H}")

# Try to get a reasonable font
try:
    font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)
    font_label = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 16)
    font_title = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 20)
except:
    font_small = ImageFont.load_default()
    font_label = font_small
    font_title = font_small

# ── Circle centers and radii (estimated from image inspection) ─────────
# Image is 1600x1200. Three circles arranged:
#   Top-left, Top-right, Bottom-center
# N/S/E/W labels visible on each circle help calibrate.
#
# Estimated from visual inspection of the 1600x1200 image:
# Top-left:     center ~(400, 340), radius ~210
# Top-right:    center ~(1120, 340), radius ~210
# Bottom-center: center ~(755, 780), radius ~210

COMPASSES = [
    {"name": "Compass A (top-left)",   "cx": 390,  "cy": 350, "r": 205, "color": (255, 50, 50)},
    {"name": "Compass B (top-right)",  "cx": 1130, "cy": 330, "r": 215, "color": (50, 50, 255)},
    {"name": "Compass C (bottom)",     "cx": 750,  "cy": 790, "r": 210, "color": (50, 180, 50)},
]


def overlay_degree_ring(draw, cx, cy, r, color, name):
    """Draw a graduated degree ring around a compass circle."""

    # Draw the degree ring slightly outside the original circle
    ring_r = r + 8

    # Tick marks every 5 degrees, longer ticks every 15, labels every 15
    for deg in range(0, 360):
        rad = math.radians(deg - 90)  # -90 because 0°=North=top

        if deg % 5 != 0:
            continue

        # Tick length — bolder and more visible
        if deg % 45 == 0:  # Major cardinals + intercardinals
            tick_inner = ring_r - 6
            tick_outer = ring_r + 18
            tick_width = 3
        elif deg % 15 == 0:
            tick_inner = ring_r - 3
            tick_outer = ring_r + 14
            tick_width = 2
        else:  # every 5°
            tick_inner = ring_r
            tick_outer = ring_r + 8
            tick_width = 1

        x_inner = cx + tick_inner * math.cos(rad)
        y_inner = cy + tick_inner * math.sin(rad)
        x_outer = cx + tick_outer * math.cos(rad)
        y_outer = cy + tick_outer * math.sin(rad)

        draw.line([(x_inner, y_inner), (x_outer, y_outer)],
                  fill=color, width=tick_width)

        # Labels every 15 degrees for better resolution
        if deg % 15 == 0:
            label_r = ring_r + 24
            lx = cx + label_r * math.cos(rad)
            ly = cy + label_r * math.sin(rad)

            text = str(deg)
            # Get text size for centering
            bbox = draw.textbbox((0, 0), text, font=font_small)
            tw = bbox[2] - bbox[0]
            th = bbox[3] - bbox[1]

            draw.text((lx - tw/2, ly - th/2), text, fill=color, font=font_small)

    # Cardinal direction labels at ring edge
    cardinals = [(0, "N"), (90, "E"), (180, "S"), (270, "W")]
    for deg, label in cardinals:
        rad = math.radians(deg - 90)
        lr = ring_r + 42
        lx = cx + lr * math.cos(rad)
        ly = cy + lr * math.sin(rad)
        bbox = draw.textbbox((0, 0), label, font=font_label)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
        draw.text((lx - tw/2, ly - th/2), label, fill=color, font=font_label)

    # Draw thin circle at the ring radius
    draw.ellipse([(cx - ring_r, cy - ring_r), (cx + ring_r, cy + ring_r)],
                 outline=color, width=1)

    # Draw crosshair at center
    ch = 8
    draw.line([(cx - ch, cy), (cx + ch, cy)], fill=color, width=1)
    draw.line([(cx, cy - ch), (cx, cy + ch)], fill=color, width=1)

    # Name label
    draw.text((cx - 80, cy + ring_r + 48), name, fill=color, font=font_label)


# ── Apply overlays ─────────────────────────────────────────────────────

for compass in COMPASSES:
    overlay_degree_ring(draw, compass["cx"], compass["cy"],
                        compass["r"], compass["color"], compass["name"])

# Title
draw.text((20, 20), "IMG_1518 — Sanborn Compass Rose Studies",
          fill=(200, 200, 200), font=font_title)
draw.text((20, 45), "Degree overlay for needle angle measurement",
          fill=(180, 180, 180), font=font_small)
draw.text((20, 65), "0° = N (top), clockwise. Red=A, Blue=B, Green=C",
          fill=(180, 180, 180), font=font_small)

# Save
os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
img.save(OUTPUT, quality=95)
print(f"Saved: {OUTPUT}")
print(f"Open with: xdg-open {OUTPUT}")
