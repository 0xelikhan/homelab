#!/bin/sh
# Automated dark-web malware crawl (one rotating slice), sample triage, dashboard rebuild.
# The crawl itself is read-only; triage.py then PULLS the flagged sample links into
# ~/quarantine, statically verifies them (file/pefile/DIE/YARA/capa), deletes false
# positives, and keeps only real malicious executables for the REs. Nothing is executed.
cd /home/user/Desktop/cti || exit 1
python3 harvest-mirrors.py 2>/dev/null
python3 crawl-sources.py
sh /home/user/Desktop/cti/tg-collect.sh 2>/dev/null   # Telegram sample pull (no-op until account set up)
python3 triage.py 2>/dev/null
python3 build-dashboard.py
