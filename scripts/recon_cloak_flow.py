#!/usr/bin/env python3
"""Stealth browser recon flow for wallet-on-telegram targets.

Reads existing live URL sources, loads each in headless Chromium with
light stealth settings, records resolved/title/status signals, and
writes results to ~/projects/bugbounty/scans/stealth_recon_<date>/live_urls.txt.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import TimeoutError as PlaywrightTimeout, sync_playwright

PROJECT = Path.home() / "projects" / "bugbounty"
SOURCE_FILES = [
    PROJECT / "scans" / "wallet-on-telegram" / "live_urls.txt",
    PROJECT / "scans" / "wallet-on-telegram" / "live-urls.txt",
    PROJECT / "scans" / "wallet-on-telegram" / "httpx-live.txt",
    PROJECT / "bugbounty" / "scans" / "quizlet" / "recon" / "live_hosts.txt",
    PROJECT / "bugbounty" / "scans" / "glean" / "recon" / "live_hosts.txt",
    PROJECT / "bugbounty" / "scans" / "fivetran" / "recon" / "live_hosts.txt",
    PROJECT / "bugbounty" / "scans" / "asana" / "recon" / "live_hosts.txt",
    PROJECT / "bugbounty" / "scans" / "afterpay" / "recon" / "live_hosts.txt",
    PROJECT / "bugbounty" / "scans" / "acorns.com" / "recon" / "live_hosts.txt",
]


def collect_urls() -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for path in SOURCE_FILES:
        if not path.exists():
            continue
        for line in path.read_text(errors="ignore").splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            url = raw.split()[0]
            if url.startswith("http://") or url.startswith("https://"):
                normalized = url.rstrip("/")
                if normalized not in seen:
                    seen.add(normalized)
                    urls.append(normalized)
    return urls


STEALTH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-setuid-sandbox",
    "--no-sandbox",
    "--disable-accelerated-2d-canvas",
    "--window-size=1280,2200",
]


def run() -> int:
    urls = collect_urls()
    if not urls:
        print("No URLs collected from source files.", file=sys.stderr)
        return 2

    today = datetime.now().strftime("%Y%m%d")
    out_dir = PROJECT / "scans" / f"stealth_recon_{today}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "live_urls.txt"
    raw_path = out_dir / "raw.json"

    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=STEALTH_ARGS)
        context = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/126.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 2200},
            locale="en-US",
            timezone_id="UTC",
            color_scheme="light",
        )
        try:
            for idx, url in enumerate(urls, 1):
                print(f"[{idx}/{len(urls)}] probing {url}", flush=True)

                page = context.new_page()
                out: dict = {
                    "url": url,
                    "final_url": "",
                    "title": "",
                    "status": None,
                    "error": "",
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "signals": {},
                }
                try:
                    resp = page.goto(url, wait_until="domcontentloaded", timeout=22000)
                    out["final_url"] = page.url
                    out["title"] = (page.title() or "").strip().replace("\n", " ")
                    out["status"] = resp.status if resp else None
                    sig = page.evaluate(
                        "() => ({"
                        "webdriver: navigator.webdriver,"
                        "languages: Array.from(navigator.languages || []).slice(0,3),"
                        "plugins: navigator.plugins.length"
                        "})"
                    )
                    out["signals"] = sig
                except PlaywrightTimeout:
                    out["error"] = "timeout"
                except Exception as exc:  # pragma: no cover - best-effort probe
                    out["error"] = str(exc)[:240].replace("\n", " ")
                finally:
                    try:
                        page.close()
                    except Exception:
                        pass

                results.append(out)
                time.sleep(0.35)
        finally:
            context.close()
            browser.close()

    live_text_lines = [
        (
            f"{res['url']}\t"
            f"status={res.get('status')}\t"
            f"final={res.get('final_url')}\t"
            f"title={res.get('title')}\t"
            f"error={res.get('error') or '-'}"
        )
        for res in results
    ]
    out_path.write_text("\n".join(live_text_lines) + "\n", encoding="utf-8")
    raw_path.write_text(
        json.dumps({"date": today, "count": len(results), "targets": results}, indent=2),
        encoding="utf-8",
    )
    print(f"Wrote {len(results)} results -> {out_path}")
    print(f"Raw JSON -> {raw_path}")
    return 0


if __name__ == "__main__":
    sys.exit(run())
