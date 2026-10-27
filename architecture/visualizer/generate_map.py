#!/usr/bin/env python3
"""Generate architecture/lab-map.svg: a visual map of the home lab.

Shows the VLAN zones, the machines in each, and the CTI pipeline. Deliberately
contains no IP addresses or hostnames, only zone purpose and tool names, so it
is safe to publish. Re-run after changing LAB below.

    python architecture/visualizer/generate_map.py
"""
from pathlib import Path
from html import escape

OUT = Path(__file__).resolve().parent.parent / "lab-map.svg"

# Zones: (key, title, subtitle, color, [machines])
ZONES = [
    ("soc", "VLAN 10 - SOC", "detect / hunt / respond", "#2563eb",
     ["Wazuh  (SIEM)", "Velociraptor  (DFIR)", "ElastAlert", "DFIR-IRIS",
      "n8n  (SOAR)", "NSM sensor  (Zeek/Suricata)", "FMD  (device finder)"]),
    ("cti", "VLAN 10 - CTI", "intel / enrich / share", "#0891b2",
     ["MISP", "OpenCTI", "TheHive + Cortex", "Hermes Agent", "attack-tools"]),
    ("victim", "VLAN 20 - Victim", "targets / deception", "#ea580c",
     ["DC01  (Active Directory)", "Metasploitable", "OpenCanary + Cowrie"]),
    ("attack", "VLAN 30 - Attacker", "offensive", "#dc2626",
     ["Kali  (attack box)"]),
    ("servers", "VLAN 40 - Servers", "app / container targets", "#16a34a",
     ["web-01  (DVWA)", "k8s-01  (MicroK8s + Falco)"]),
    ("malware", "VLAN 99 - Malware", "isolated - NO internet", "#7c3aed",
     ["FLARE-VM", "CAPEv2 sandbox"]),
]

# CTI pipeline stages (left to right)
PIPELINE = ["Feeds\nabuse.ch / OTX / RSS / KEV", "MISP + OpenCTI\ncorrelate",
            "Hermes Agent\nenrich + summarize", "Telegram\ndaily / weekly briefs"]

W = 1280
COL_W = 196
GAP = 14
X0 = 28
HEADER_Y = 190
PILL_H = 30
PILL_GAP = 7


def rrect(x, y, w, h, r, fill, stroke="none", sw=1, extra=""):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" ry="{r}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}" {extra}/>')


def text(x, y, s, size=13, fill="#0f172a", weight="normal", anchor="start", family="Segoe UI, Arial, sans-serif"):
    return (f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
            f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{escape(s)}</text>')


def build():
    parts = []
    # compute height
    max_rows = max(len(m) for _, _, _, _, m in ZONES)
    zones_bottom = HEADER_Y + 44 + max_rows * (PILL_H + PILL_GAP) + 16
    pipe_y = zones_bottom + 34
    H = pipe_y + 120

    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="Segoe UI, Arial, sans-serif">')
    parts.append(rrect(0, 0, W, H, 0, "#f8fafc"))
    parts.append(text(W / 2, 42, "Home Lab - CTI / SOC range", 24, "#0f172a", "700", "middle"))
    parts.append(text(W / 2, 66, "Proxmox VE - pfSense-segmented VLANs - CTI pipeline to Telegram", 13, "#64748b", "normal", "middle"))

    # internet -> pfSense
    parts.append(rrect(W / 2 - 70, 90, 140, 30, 15, "#e2e8f0", "#94a3b8", 1))
    parts.append(text(W / 2, 110, "Internet", 13, "#475569", "600", "middle"))
    parts.append(f'<line x1="{W/2}" y1="120" x2="{W/2}" y2="140" stroke="#94a3b8" stroke-width="2"/>')
    parts.append(rrect(X0, 140, W - 2 * X0, 36, 8, "#1e293b"))
    parts.append(text(W / 2, 163, "pfSense  -  router / firewall / NAT  -  per-VLAN rules", 14, "#f1f5f9", "600", "middle"))

    # zones
    n = len(ZONES)
    total = n * COL_W + (n - 1) * GAP
    start_x = (W - total) / 2
    for i, (key, title, sub, color, machines) in enumerate(ZONES):
        x = start_x + i * (COL_W + GAP)
        # connector from pfSense bar
        parts.append(f'<line x1="{x+COL_W/2}" y1="176" x2="{x+COL_W/2}" y2="{HEADER_Y}" stroke="{color}" stroke-width="2"/>')
        # header
        parts.append(rrect(x, HEADER_Y, COL_W, 44, 8, color))
        parts.append(text(x + COL_W / 2, HEADER_Y + 19, title, 13.5, "#ffffff", "700", "middle"))
        parts.append(text(x + COL_W / 2, HEADER_Y + 35, sub, 11, "#e2e8f0", "normal", "middle"))
        # body background
        body_h = max_rows * (PILL_H + PILL_GAP) + 10
        parts.append(rrect(x, HEADER_Y + 48, COL_W, body_h, 8, "#ffffff", color, 1.5))
        # pills
        py = HEADER_Y + 48 + 8
        for m in machines:
            parts.append(rrect(x + 8, py, COL_W - 16, PILL_H, 6, "#f1f5f9", color, 1))
            parts.append(text(x + 16, py + 19, m, 11.5, "#0f172a", "500"))
            py += PILL_H + PILL_GAP

    # CTI pipeline ribbon
    parts.append(text(W / 2, pipe_y - 8, "CTI pipeline", 15, "#0f172a", "700", "middle"))
    stages = len(PIPELINE)
    sw = 236
    sgap = 54
    stotal = stages * sw + (stages - 1) * sgap
    sx = (W - stotal) / 2
    for i, stage in enumerate(PIPELINE):
        bx = sx + i * (sw + sgap)
        parts.append(rrect(bx, pipe_y + 6, sw, 60, 10, "#ecfeff", "#0891b2", 1.5))
        lines = stage.split("\n")
        parts.append(text(bx + sw / 2, pipe_y + 30, lines[0], 13, "#0e7490", "700", "middle"))
        if len(lines) > 1:
            parts.append(text(bx + sw / 2, pipe_y + 50, lines[1], 11, "#155e75", "normal", "middle"))
        if i < stages - 1:
            ax = bx + sw + 8
            ay = pipe_y + 36
            parts.append(f'<path d="M{ax} {ay} l{sgap-16} 0 l-8 -6 m8 6 l-8 6" stroke="#0891b2" stroke-width="2.5" fill="none"/>')

    # footer
    parts.append(text(W / 2, H - 18, "No IPs or hostnames shown. lab-profile groups start/stop zones to fit 32 GB RAM.", 11, "#94a3b8", "normal", "middle"))
    parts.append('</svg>')
    return "\n".join(parts)


if __name__ == "__main__":
    OUT.write_text(build(), encoding="utf-8")
    print(f"wrote {OUT}  ({OUT.stat().st_size} bytes)")
