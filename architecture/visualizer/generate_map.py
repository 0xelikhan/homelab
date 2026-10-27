#!/usr/bin/env python3
"""Generate architecture/lab-map.svg (and render lab-map.png): a dark, carded map of the
home lab in the style of a homelab dashboard. No IP addresses or hostnames, only zone
purpose and tool names, so it is safe to publish.

    python architecture/visualizer/generate_map.py          # writes the SVG
    python architecture/visualizer/generate_map.py --png     # also renders PNG (needs playwright)
"""
import sys
from html import escape
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "lab-map.svg"

# zone: key, title, color, always_on, [services]
ZONES = [
    ("cti", "VLAN 10 · CTI", "#22d3ee", True,
     ["MISP", "OpenCTI", "TheHive + Cortex", "Hermes Agent", "attack-tools"]),
    ("soc", "VLAN 10 · SOC", "#3b82f6", False,
     ["Wazuh", "Velociraptor", "ElastAlert", "DFIR-IRIS", "n8n (SOAR)", "NSM sensor", "FMD"]),
    ("victim", "VLAN 20 · Victim", "#f59e0b", False,
     ["DC01 (AD)", "Metasploitable", "OpenCanary + Cowrie"]),
    ("attack", "VLAN 30 · Attacker", "#ef4444", False,
     ["Kali"]),
    ("servers", "VLAN 40 · Servers", "#22c55e", False,
     ["web-01 (DVWA)", "k8s-01 (MicroK8s)"]),
    ("malware", "VLAN 99 · Malware", "#a855f7", False,
     ["FLARE-VM", "CAPEv2"]),
]
PIPELINE = [("Feeds", "abuse.ch · OTX · RSS · KEV"), ("MISP + OpenCTI", "correlate"),
            ("Hermes", "enrich + summarize"), ("Telegram", "daily / weekly briefs")]

# palette
BG = "#0b0f17"
CARD = "#141b27"
CARD_STROKE = "#243042"
CONTAINER = "#0e1420"
TEXT = "#e5edf5"
MUTED = "#8aa0b6"
GREEN = "#22c55e"
AMBER = "#f59e0b"

W = 1400
MARGIN = 34
GAP = 16
CARD_H = 34
CARD_GAP = 9
HEAD = 40
ZONE_TOP = 250


def rect(x, y, w, h, r, fill, stroke="none", sw=1, op=1.0):
    o = f' stroke-opacity="{op}"' if op != 1.0 else ""
    return f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{o}/>'


def txt(x, y, s, size=12, fill=TEXT, weight="400", anchor="start"):
    return f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{escape(s)}</text>'


def dot(x, y, color):
    return f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" fill="{color}"/>'


def build():
    n = len(ZONES)
    cw = (W - 2 * MARGIN - (n - 1) * GAP) / n
    heights = [HEAD + len(m) * (CARD_H + CARD_GAP) + 12 for *_, m in ZONES]
    zones_bottom = ZONE_TOP + max(heights)
    pipe_y = zones_bottom + 46
    H = pipe_y + 150

    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {int(H)}" '
         f'font-family="\'Segoe UI\',Helvetica,Arial,sans-serif">']
    s.append(rect(0, 0, W, H, 0, BG))
    # title
    s.append(txt(MARGIN, 52, "Home Lab", 26, TEXT, "700"))
    s.append(txt(MARGIN + 142, 52, "CTI / SOC range", 26, MUTED, "300"))
    s.append(txt(MARGIN, 76, "Proxmox VE · pfSense-segmented VLANs · threat-intel pipeline to Telegram", 13, MUTED))

    # internet -> pfSense
    cx = W / 2
    s.append(rect(cx - 62, 100, 124, 30, 15, "#1b2432", "#33415a", 1))
    s.append(txt(cx, 120, "Internet", 12.5, MUTED, "600", "middle"))
    s.append(f'<line x1="{cx}" y1="130" x2="{cx}" y2="150" stroke="#33415a" stroke-width="1.5"/>')
    pf_y = 150
    s.append(rect(cx - 190, pf_y, 380, 50, 10, "#10243180", "#22d3ee", 1.5))
    s.append(dot(cx - 190 + 16, pf_y + 16, GREEN))
    s.append(txt(cx - 190 + 30, pf_y + 20, "pfSense", 14, TEXT, "700"))
    s.append(txt(cx - 190 + 30, pf_y + 38, "router · firewall · NAT · per-VLAN rules", 11.5, MUTED))
    pf_bottom = pf_y + 50

    # zones
    for i, (key, title, color, always, machines) in enumerate(ZONES):
        x = MARGIN + i * (cw + GAP)
        zh = heights[i]
        # connector pfSense -> container top
        tx = x + cw / 2
        my = (pf_bottom + ZONE_TOP) / 2
        s.append(f'<path d="M{cx:.0f} {pf_bottom} C {cx:.0f} {my:.0f}, {tx:.0f} {my:.0f}, {tx:.0f} {ZONE_TOP}" '
                 f'stroke="{color}" stroke-opacity="0.45" stroke-width="1.5" fill="none"/>')
        # container
        s.append(rect(x, ZONE_TOP, cw, zh, 12, CONTAINER, color, 1.4, 0.4))
        s.append(f'<rect x="{x:.1f}" y="{ZONE_TOP}" width="4" height="{zh:.1f}" rx="2" fill="{color}"/>')
        s.append(txt(x + 14, ZONE_TOP + 25, title, 12.5, color, "700"))
        if always:
            s.append(txt(x + cw - 12, ZONE_TOP + 25, "always on", 9.5, GREEN, "400", "end"))
        # cards
        cyv = ZONE_TOP + HEAD
        for m in machines:
            s.append(rect(x + 10, cyv, cw - 20, CARD_H, 7, CARD, CARD_STROKE, 1))
            s.append(rect(x + 19, cyv + 11, 12, 12, 3, color))
            s.append(txt(x + 40, cyv + 22, m, 11.5, TEXT, "500"))
            s.append(dot(x + cw - 20, cyv + 17, GREEN if always else AMBER))
            cyv += CARD_H + CARD_GAP

    # CTI pipeline
    s.append(txt(MARGIN, pipe_y + 6, "CTI pipeline", 15, TEXT, "700"))
    stages = len(PIPELINE)
    sgap = 48
    sw = (W - 2 * MARGIN - (stages - 1) * sgap) / stages
    for i, (h1, h2) in enumerate(PIPELINE):
        bx = MARGIN + i * (sw + sgap)
        by = pipe_y + 20
        s.append(rect(bx, by, sw, 62, 10, "#0e2230", "#22d3ee", 1.4))
        s.append(txt(bx + sw / 2, by + 28, h1, 14, "#67e8f9", "700", "middle"))
        s.append(txt(bx + sw / 2, by + 48, h2, 11, MUTED, "400", "middle"))
        if i < stages - 1:
            ax = bx + sw + 8
            ay = by + 31
            s.append(f'<path d="M{ax:.0f} {ay} l{sgap-16} 0 l-7 -5 m7 5 l-7 5" stroke="#22d3ee" stroke-width="2.2" fill="none"/>')

    # legend
    ly = H - 34
    s.append(dot(MARGIN + 6, ly - 4, GREEN))
    s.append(txt(MARGIN + 18, ly, "always on (cti group)", 11, MUTED))
    s.append(dot(MARGIN + 190, ly - 4, AMBER))
    s.append(txt(MARGIN + 202, ly, "on-demand (started per lab-profile group)", 11, MUTED))
    s.append(txt(W - MARGIN, ly, "No IPs or hostnames shown · generated from generate_map.py", 11, "#5a6b7e", "400", "end"))

    s.append("</svg>")
    return "\n".join(s)


def render_png():
    from playwright.sync_api import sync_playwright
    svg = OUT.read_text(encoding="utf-8")
    png = OUT.with_suffix(".png")
    html = f"<!doctype html><html><head><meta charset='utf-8'><style>*{{margin:0;padding:0}}</style></head><body>{svg}</body></html>"
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(device_scale_factor=2)
        pg.set_content(html)
        el = pg.query_selector("svg")
        el.screenshot(path=str(png))
        b.close()
    print(f"wrote {png}")


if __name__ == "__main__":
    OUT.write_text(build(), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
    if "--png" in sys.argv:
        render_png()
