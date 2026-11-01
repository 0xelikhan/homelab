# Research-VM CTI dashboard

Landing page for the Whonix research Workstation: a live ransomware leak-site feed plus a deduped, collapsible directory of ~2,500 dark-web CTI sources. No JavaScript, so it works at Tor Browser "Safest".

| File | What |
|---|---|
| [gen_sources.py](gen_sources.py) | Parses `../deepdarkcti/*.md` into the deduped `sources.json` |
| [sources.json](sources.json) | Categorized, deduped source directory data |
| [build-dashboard.py](build-dashboard.py) | Builds `dashboard.html`: live pull (ransomware.live + RansomLook, over Tor) + the directory |

On the Workstation this lives at `/home/user/cti/` and runs on login (autostart) to refresh the live feed. `dashboard.html` is generated, not committed.
