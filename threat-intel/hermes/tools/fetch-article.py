#!/usr/bin/env python3
"""fetch-article.py — fetch and extract full article text from a URL.

Used by the daily brief pipeline to replace the RSS-feed excerpt that OpenCTI
stores with the full article body. Falls back cleanly on paywalls, Cloudflare
blocks, JS-only pages, and network errors — the caller decides whether to use
the OpenCTI description instead.

Usage:
    python3 tools/clis/fetch-article.py <url> [--max-chars N]

Output (JSON, one line):
    source   "full"    — full article extracted, within max-chars
             "partial" — extracted but truncated to max-chars
             "failed"  — could not fetch or extract; use OpenCTI description
    text     extracted article body (up to max-chars characters)
    length   len(text)
    note     "" on full success; reason string on failed/partial
"""
import argparse, json, sys

MAX_CHARS = 8000  # enough for a full security article; keeps brief context sane


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--max-chars", type=int, default=MAX_CHARS)
    a = ap.parse_args()

    try:
        import trafilatura
    except ImportError:
        _out("failed", "", "trafilatura not installed — pip3 install trafilatura")
        return

    try:
        downloaded = trafilatura.fetch_url(a.url)
    except Exception as e:
        _out("failed", "", f"fetch error: {type(e).__name__}: {str(e)[:120]}")
        return

    if not downloaded:
        _out("failed", "", "no content returned (paywall, Cloudflare block, or redirect loop)")
        return

    text = trafilatura.extract(
        downloaded,
        include_comments=False,
        include_tables=False,
        no_fallback=False,
        favor_precision=True,
    )

    if not text:
        _out("failed", "", "extraction returned nothing (JS-rendered page or extraction failure)")
        return

    if len(text) > a.max_chars:
        _out("partial", text[: a.max_chars], f"truncated to {a.max_chars} chars (full: {len(text)})")
    else:
        _out("full", text, "")


def _out(source, text, note):
    print(json.dumps({"source": source, "text": text, "length": len(text), "note": note}))


if __name__ == "__main__":
    main()
