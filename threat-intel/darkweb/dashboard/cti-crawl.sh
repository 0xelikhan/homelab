#!/bin/sh
# Automated READ-ONLY dark-web malware crawl (one rotating slice) + dashboard rebuild.
cd /home/user/Desktop/cti || exit 1
python3 harvest-mirrors.py 2>/dev/null
python3 crawl-sources.py
python3 build-dashboard.py
