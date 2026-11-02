#!/bin/sh
# Research-VM dashboard refresh (run on login via autostart, or manually).
# Fetches just the source .md files we use from raw.githubusercontent over Tor
# (lighter + more reliable than a full git clone), with retries and keep-last-good,
# then regenerates the directory and rebuilds the dashboard. All traffic is Tor-routed.
cd "$(dirname "$0")" || exit 1
mkdir -p deepdarkCTI
BASE="https://raw.githubusercontent.com/fastfire/deepdarkCTI/main"
FILES="ransomware_gang telegram_threat_actors telegram_infostealer forum markets search_engines others commercial_services"

have=0; want=0
for f in $FILES; do
    want=$((want + 1))
    for try in 1 2 3; do
        if curl -fsS -m 60 "$BASE/$f.md" -o "deepdarkCTI/$f.md.tmp" && [ -s "deepdarkCTI/$f.md.tmp" ]; then
            mv "deepdarkCTI/$f.md.tmp" "deepdarkCTI/$f.md"
            break
        fi
        rm -f "deepdarkCTI/$f.md.tmp"
        sleep 5
    done
    [ -s "deepdarkCTI/$f.md" ] && have=$((have + 1))   # counts new OR last-good copies
done

# Only regenerate the directory if we have a complete set; otherwise keep last-good sources.json.
[ "$have" -eq "$want" ] && python3 gen_sources.py >/dev/null 2>&1
python3 build-dashboard.py
