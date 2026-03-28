#!/usr/bin/env python3
"""
Batch triage script for Archives of American Art image corpus.
Converts HEIC → small JPG thumbnails for rapid visual review,
and generates a manifest of all images with metadata.
"""

import json
import os
import sys
from pathlib import Path

try:
    from PIL import Image
    from pillow_heif import register_heif_opener
    register_heif_opener()
except ImportError:
    print("ERROR: Requires pillow-heif. Run: pip install pillow-heif")
    sys.exit(1)

ARCHIVE_DIR = Path("/home/cpatrick/kryptos/reference/Pictures/Arichives of American Art")
STATIC_ARCHIVE = Path("/home/cpatrick/kryptos/ops/site_builder/static/archive")
THUMB_DIR = Path("/tmp/archive_thumbs")
MANIFEST_PATH = Path("/home/cpatrick/kryptos/ops/site_builder/archive_manifest.json")

# Images currently on the page
CURRENT_IMAGES = {
    1092, 1142, 1152, 1192, 1202, 1211, 1212, 1213, 1214, 1218,
    1219, 1220, 1221, 1222, 1223, 1225, 1236, 1237, 1238, 1239,
    1240, 1281, 1291, 1381, 1382, 1491, 1540, 1541, 1542, 1551,
    1560, 1561, 1571, 1574, 1581, 1591
}


def get_image_number(filename):
    """Extract numeric ID from IMG_NNNN.HEIC filename."""
    base = Path(filename).stem
    if base.startswith("IMG_"):
        try:
            return int(base[4:])
        except ValueError:
            return None
    return None


def convert_batch(start, end, max_size=800):
    """Convert a range of HEIC images to JPG thumbnails."""
    THUMB_DIR.mkdir(exist_ok=True)
    converted = []

    for f in sorted(ARCHIVE_DIR.iterdir()):
        if not f.suffix.upper() == '.HEIC':
            continue
        num = get_image_number(f.name)
        if num is None or num < start or num > end:
            continue

        out_path = THUMB_DIR / f"IMG_{num}.jpg"
        if out_path.exists():
            converted.append((num, out_path))
            continue

        try:
            img = Image.open(f)
            img.thumbnail((max_size, max_size), Image.LANCZOS)
            img.save(out_path, "JPEG", quality=75)
            converted.append((num, out_path))
        except Exception as e:
            print(f"  FAIL: IMG_{num} — {e}")

    return converted


def convert_for_web(num, max_size=1600, quality=82):
    """Convert a single HEIC to publication-quality JPG in static/archive."""
    src = ARCHIVE_DIR / f"IMG_{num}.HEIC"
    if not src.exists():
        print(f"  NOT FOUND: {src}")
        return None

    STATIC_ARCHIVE.mkdir(exist_ok=True)
    dst = STATIC_ARCHIVE / f"IMG_{num}.jpg"

    try:
        img = Image.open(src)
        img.thumbnail((max_size, max_size), Image.LANCZOS)
        img.save(dst, "JPEG", quality=quality)
        size_kb = dst.stat().st_size / 1024
        print(f"  IMG_{num}.jpg — {img.size[0]}x{img.size[1]} — {size_kb:.0f} KB")
        return dst
    except Exception as e:
        print(f"  FAIL: IMG_{num} — {e}")
        return None


def build_manifest(selections):
    """Build and save the triage manifest."""
    manifest = {
        "generated": "2026-03-28",
        "source": "Archives of American Art, Smithsonian Institution",
        "collection": "Jim Sanborn papers, circa 1950-2023",
        "total_corpus": 532,
        "selections": selections,
    }
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Manifest written to {MANIFEST_PATH}")
    return manifest


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Archive image triage")
    parser.add_argument("--thumbs", type=str, help="Convert range: START-END")
    parser.add_argument("--web", type=str, help="Convert for web: comma-separated numbers")
    parser.add_argument("--list-current", action="store_true", help="List currently included images")
    parser.add_argument("--gaps", action="store_true", help="Show images NOT on current page")

    args = parser.parse_args()

    if args.thumbs:
        start, end = map(int, args.thumbs.split("-"))
        print(f"Converting thumbnails for IMG_{start} to IMG_{end}...")
        results = convert_batch(start, end)
        print(f"Converted {len(results)} images to {THUMB_DIR}/")

    elif args.web:
        nums = [int(x.strip()) for x in args.web.split(",")]
        print(f"Converting {len(nums)} images for web publication...")
        for num in nums:
            convert_for_web(num)

    elif args.list_current:
        print(f"Current page images ({len(CURRENT_IMAGES)}):")
        for n in sorted(CURRENT_IMAGES):
            print(f"  IMG_{n}")

    elif args.gaps:
        all_nums = set()
        for f in ARCHIVE_DIR.iterdir():
            num = get_image_number(f.name)
            if num is not None:
                all_nums.add(num)
        missing = sorted(all_nums - CURRENT_IMAGES)
        print(f"Images NOT on current page ({len(missing)} of {len(all_nums)}):")
        for n in missing:
            print(f"  IMG_{n}")

    else:
        parser.print_help()
