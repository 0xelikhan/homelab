#!/bin/sh
# Research-VM dashboard refresh (on login via autostart, or manually).
# Pulls the deepdarkCTI source lists over Tor (keep-last-good) and rebuilds the
# dashboard from the latest crawl findings. The malware crawl itself runs on a
# timer (cti-crawl.timer), not here, so login stays fast.
cd "$(dirname "$0")" || exit 1
mkdir -p deepdarkCTI
BASE="https://raw.githubusercontent.com/fastfire/deepdarkCTI/main"
FILES="ransomware_gang telegram_threat_actors telegram_infostealer forum markets search_engines others commercial_services"
have=0; want=0
for f in $FILES; do
    want=$((want + 1))
    for try in 1 2 3; do
        if curl -fsS -m 60 "$BASE/$f.md" -o "deepdarkCTI/$f.md.tmp" && [ -s "deepdarkCTI/$f.md.tmp" ]; then
            mv "deepdarkCTI/$f.md.tmp" "deepdarkCTI/$f.md"; break
        fi
        rm -f "deepdarkCTI/$f.md.tmp"; sleep 5
    done
    [ -s "deepdarkCTI/$f.md" ] && have=$((have + 1))
done
[ "$have" -eq "$want" ] && python3 gen_sources.py >/dev/null 2>&1
python3 build-dashboard.py
