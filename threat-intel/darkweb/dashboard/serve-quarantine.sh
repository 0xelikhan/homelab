#!/bin/sh
# Local-only quarantine file server. The dashboard runs in Tor Browser, which blocks
# file:// links, but it can reach 127.0.0.1. This serves ~/quarantine (one folder per
# sample, each holding the sample + findings.txt) so the dashboard's folder links work.
# Bound to 127.0.0.1 only: never reachable off the VM. Idempotent (no-op if already up).
pgrep -f "http.server 8777" >/dev/null 2>&1 && exit 0
mkdir -p /home/user/quarantine
nohup python3 -m http.server 8777 --bind 127.0.0.1 --directory /home/user/quarantine \
      >/tmp/qserve.log 2>&1 &
