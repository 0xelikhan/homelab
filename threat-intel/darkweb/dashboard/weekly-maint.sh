#!/bin/sh
# Weekly source-list maintenance. Refreshes the curated deepdarkCTI source lists over
# Tor (adds newly-listed sources, drops ones upstream removed), regenerates sources.json,
# and rebuilds the dashboard. The ~2h crawl's harvest-mirrors.py separately keeps the
# onion leak-site mirror seeds pruned + current. Wired to cti-weekly.timer (OnCalendar=weekly).
cd /home/user/Desktop/cti || exit 1
sh refresh-all.sh
