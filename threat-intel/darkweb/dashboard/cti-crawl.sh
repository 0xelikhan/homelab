#!/bin/sh
# Automated dark-web malware crawl (one rotating slice), sample triage, dashboard rebuild.
# The crawl itself is read-only; triage.py then PULLS the flagged sample links into
# ~/quarantine, statically verifies them (file/pefile/DIE/YARA/capa), deletes false
# positives, and keeps only real malicious executables for the REs. Nothing is executed.
cd /home/user/Desktop/cti || exit 1
python3 harvest-mirrors.py 2>/dev/null         # refresh live onion leak mirrors
python3 crawl-sources.py                        # scrape ALL source categories -> candidates
python3 tg-public.py 2>/dev/null                # account-free sweep of public TG channels -> candidates
sh /home/user/Desktop/cti/tg-collect.sh 2>/dev/null   # account-based TG attachments -> tg-intake (no-op w/o session)
python3 vx-intake.py 2>/dev/null                # process vx-underground archives in vx-intake -> triage
python3 triage.py 2>/dev/null                   # pull candidates + tg-intake, verify -> quarantine
python3 build-dashboard.py                      # render verified executables
