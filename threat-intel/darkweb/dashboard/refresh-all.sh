#!/bin/sh
# Research-VM dashboard refresh (run on login via autostart, or manually).
# Pulls the live deepdarkCTI source lists over Tor, regenerates the directory,
# and rebuilds the dashboard. All network traffic is transparently Tor-routed.
cd "$(dirname "$0")" || exit 1
git -C deepdarkCTI pull -q 2>/dev/null || git clone -q --depth 1 https://github.com/fastfire/deepdarkCTI 2>/dev/null
python3 gen_sources.py >/dev/null 2>&1
python3 build-dashboard.py
