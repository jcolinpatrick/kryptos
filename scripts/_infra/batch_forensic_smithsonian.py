#!/usr/bin/env python3
"""Batch forensic analysis of all Smithsonian archive images.

Runs the full forensic photo pipeline on every image in the Smithsonian
archive directories. Outputs organized by box/folder/image.

Usage: source venv/bin/activate && python3 scripts/_infra/batch_forensic_smithsonian.py
"""
import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).parent.parent.parent
SMITHSONIAN_DIR = PROJECT_ROOT / "reference" / "Pictures" / "Smithsonian"
OUTPUT_BASE = PROJECT_ROOT / "results" / "forensic" / "smithsonian_batch"
ANALYZER = PROJECT_ROOT / "ops" / "tools" / "photo_analysis" / "forensic_photo_analyzer.py"

# Full pipeline minus OCR (slow) — add ocr for text-heavy images separately
MODULES = "ela,fft,chi_square,noise_residual,channel,statistical,lsb,metadata"

def main():
    # Find all images
    images = sorted(SMITHSONIAN_DIR.rglob("*.jpg"))
    print(f"Found {len(images)} images in {SMITHSONIAN_DIR}")
    print(f"Output: {OUTPUT_BASE}")
    print(f"Modules: {MODULES}")
    print(f"Start: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    results_summary = []
    
    for i, img_path in enumerate(images):
        folder_name = img_path.parent.name  # e.g., sanbojim-box-6-folder-18
        img_name = img_path.stem.split("-")[0]  # e.g., "1" from "1-AAA-AAA_..."
        
        out_dir = OUTPUT_BASE / folder_name / f"img_{img_name}"
        
        # Skip if already processed
        summary_file = out_dir / "SUMMARY.md"
        if summary_file.exists():
            print(f"  [{i+1}/{len(images)}] SKIP (exists): {folder_name}/{img_name}")
            # Still collect existing results
            report_file = out_dir / "forensic_report.json"
            if report_file.exists():
                with open(report_file) as f:
                    report = json.load(f)
                anomaly_count = len(report.get("anomalies", []))
                results_summary.append({
                    "folder": folder_name, "image": img_name,
                    "anomalies": anomaly_count, "status": "cached"
                })
            continue
        
        print(f"  [{i+1}/{len(images)}] Analyzing: {folder_name}/{img_name}...", end="", flush=True)
        
        try:
            result = subprocess.run(
                [sys.executable, str(ANALYZER), "analyze", str(img_path),
                 "-m", MODULES, "-o", str(out_dir)],
                capture_output=True, text=True, timeout=120
            )
            
            # Parse anomaly count from output
            anomaly_count = 0
            for line in result.stdout.split("\n"):
                if "ALERT:" in line:
                    anomaly_count += 1
            
            status = "ok" if result.returncode == 0 else "error"
            print(f" {anomaly_count} anomalies [{status}]")
            
            results_summary.append({
                "folder": folder_name, "image": img_name,
                "anomalies": anomaly_count, "status": status,
                "alerts": [l.strip() for l in result.stdout.split("\n") if "ALERT:" in l]
            })
            
        except subprocess.TimeoutExpired:
            print(f" TIMEOUT")
            results_summary.append({
                "folder": folder_name, "image": img_name,
                "anomalies": -1, "status": "timeout"
            })
        except Exception as e:
            print(f" ERROR: {e}")
            results_summary.append({
                "folder": folder_name, "image": img_name,
                "anomalies": -1, "status": f"error: {e}"
            })
    
    # Write batch summary
    print("\n" + "=" * 60)
    print("BATCH COMPLETE")
    
    # Sort by anomaly count descending
    interesting = [r for r in results_summary if r["anomalies"] > 0]
    interesting.sort(key=lambda r: r["anomalies"], reverse=True)
    
    print(f"\nImages with anomalies: {len(interesting)}/{len(results_summary)}")
    print("\nTop anomaly images:")
    for r in interesting[:20]:
        alerts_str = "; ".join(r.get("alerts", [])[:3])
        print(f"  {r['folder']}/{r['image']}: {r['anomalies']} anomalies — {alerts_str}")
    
    # Save summary JSON
    summary_path = OUTPUT_BASE / "batch_summary.json"
    OUTPUT_BASE.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_images": len(images),
            "total_with_anomalies": len(interesting),
            "results": results_summary,
        }, f, indent=2)
    print(f"\nSummary: {summary_path}")


if __name__ == "__main__":
    main()
