#!/usr/bin/env python3
"""Screenshot pages of the site so visual changes can be checked, not guessed.

The site is a visual artifact and was being edited blind. This renders real
pages in headless Chromium at a desktop and a phone width.

Usage:
    venv/bin/python ops/site_builder/shoot.py /methodology/ /about-kryptos/
    venv/bin/python ops/site_builder/shoot.py --live /methodology/
    venv/bin/python ops/site_builder/shoot.py --full /methodology/

Defaults to the LOCAL build directory over file:// so a change can be checked
before it is deployed. --live hits https://kryptosbot.com instead.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SITE = REPO / "site"
OUT = REPO / "site_shots"

WIDTHS = {"desktop": (1440, 900), "phone": (390, 844)}


PORT = 8971


def url_for(path: str, live: bool) -> str:
    if live:
        return "https://kryptosbot.com" + path
    # Served over HTTP, not file://, because every asset reference on the site is
    # root-absolute (/static/...) and file:// resolves those against the
    # filesystem root, so the page renders unstyled and screenshots lie.
    return f"http://127.0.0.1:{PORT}{path}"


def serve_site():
    import functools, http.server, threading
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(SITE))
    # Threaded, not the single-threaded TCPServer: a <video> element opens its
    # media request, reads the header, then stops reading while the server is
    # still blocked writing the rest of the file, so every other asset queued
    # behind it and the page never reached "load" (found on /encoding-chart/).
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _load_lazy_images(page) -> None:
    """Scroll the page so loading="lazy" images actually paint.

    A full-page screenshot does not trigger the intersection observer, so lazy
    images stay unloaded and the shot shows an empty box where the photograph is.
    That failure is silent and it makes the screenshot lie, which is the one thing
    this script exists to prevent. Scroll to the bottom in viewport-sized steps,
    return to the top, then wait for every image to report complete.
    """
    page.evaluate(
        """async () => {
            // Setting loading="eager" on a deferred image starts its fetch at
            // once (HTML spec), so this does not depend on the scroll below
            // reaching every figure. The scroll is kept for anything else that
            // is intersection-driven.
            document.querySelectorAll('img[loading="lazy"]')
                .forEach(img => { img.loading = 'eager'; });
            const step = window.innerHeight;
            // documentElement, not body: body.scrollHeight can report a single
            // viewport on this site, so the loop stopped after one step and
            // every figure past the second screen stayed unloaded.
            const total = Math.max(document.body.scrollHeight,
                                   document.documentElement.scrollHeight);
            for (let y = 0; y < total; y += step) {
                window.scrollTo(0, y);
                await new Promise(r => setTimeout(r, 120));
            }
            window.scrollTo(0, 0);
            // An <img> that is fallback content inside a supported <video> is
            // never fetched, so it never completes and never fires load/error;
            // waiting on it hung this script for good. Skip those, and cap the
            // wait so one broken image cannot stall the whole run.
            const pending = Array.from(document.images)
                .filter(img => !img.complete && !img.closest('video'))
                .map(img => new Promise(res => {
                    img.addEventListener('load', res, {once: true});
                    img.addEventListener('error', res, {once: true});
                }));
            await Promise.race([
                Promise.all(pending),
                new Promise(res => setTimeout(res, 15000)),
            ]);
        }"""
    )
    _settle(page)
    blank = page.evaluate(
        "Array.from(document.images)"
        ".filter(i => !i.closest('video'))"
        ".filter(i => !i.complete || i.naturalWidth === 0)"
        ".map(i => i.currentSrc || i.src)"
    )
    if blank:
        print(f"    WARNING: {len(blank)} image(s) never loaded: {blank[:3]}")


def _settle(page, timeout_ms: int = 10_000) -> None:
    """Wait for the network to go quiet, but not forever.

    `networkidle` never fires on a page with an autoplaying <video>: the
    browser keeps range-requesting the file, so the old unconditional wait hung
    until the outer timeout killed the run (first seen on /encoding-chart/,
    2026-09-19). Ten seconds is ample for every static asset on this site.
    """
    from playwright.sync_api import TimeoutError as PlaywrightTimeout

    try:
        page.wait_for_load_state("networkidle", timeout=timeout_ms)
    except PlaywrightTimeout:
        print("    note: network did not go idle (video streaming?); continuing")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", help="site paths, e.g. /methodology/")
    ap.add_argument("--live", action="store_true", help="shoot kryptosbot.com instead of the local build")
    ap.add_argument("--full", action="store_true", help="full-page instead of viewport")
    ap.add_argument("--only", choices=sorted(WIDTHS), help="one width only")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args(argv)

    from playwright.sync_api import sync_playwright

    httpd = None if args.live else serve_site()

    outdir = pathlib.Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    widths = {args.only: WIDTHS[args.only]} if args.only else WIDTHS
    written = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for name, (w, h) in widths.items():
            ctx = browser.new_context(viewport={"width": w, "height": h}, device_scale_factor=2)
            page = ctx.new_page()
            errors: list[str] = []
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda e: errors.append(str(e)))
            for path in args.paths:
                page.goto(url_for(path, args.live), wait_until="load")
                _settle(page)
                if args.full:
                    _load_lazy_images(page)
                slug = path.strip("/").replace("/", "-") or "home"
                f = outdir / f"{slug}--{name}.png"
                page.screenshot(path=str(f), full_page=args.full)
                written.append(f)
                print(f"  {f.relative_to(REPO)}  ({w}x{h}{', full page' if args.full else ''})")
                if errors:
                    print(f"    console errors: {errors[:3]}")
                    errors.clear()
            ctx.close()
        browser.close()
    if httpd:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
