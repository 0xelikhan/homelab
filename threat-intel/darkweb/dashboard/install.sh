#!/bin/sh
# Install the dark-web malware monitoring dashboard on a Whonix Workstation.
# Run as the normal unprivileged 'user' (no sudo needed).
#   git clone <repo> && cd <repo>/threat-intel/darkweb/dashboard && sh install.sh
#
# Files MUST live under ~/Desktop (Tor Browser's AppArmor profile only reads ~/Desktop).
set -e
DEST="$HOME/Desktop/cti"
SRC="$(cd "$(dirname "$0")" && pwd)"

echo "[1/5] installing files to $DEST"
mkdir -p "$DEST"
for f in crawl-sources.py build-dashboard.py harvest-mirrors.py gen_sources.py \
         refresh-all.sh cti-crawl.sh weekly-maint.sh extract-iocs.py ioc-paste.sh \
         sources.json actors.json; do
    cp "$SRC/$f" "$DEST/"
done
chmod +x "$DEST"/*.py "$DEST"/*.sh
mkdir -p "$HOME/onionclaw"
[ -f "$HOME/onionclaw/research-seeds.txt" ] || : > "$HOME/onionclaw/research-seeds.txt"

echo "[2/5] fetching deepdarkCTI source lists over Tor + regenerating sources.json"
( cd "$DEST" && sh refresh-all.sh ) || echo "  (fetch failed - keeping the bundled sources.json)"

echo "[3/5] installing systemd --user timers"
mkdir -p "$HOME/.config/systemd/user"
cp "$SRC/systemd/"*.service "$SRC/systemd/"*.timer "$HOME/.config/systemd/user/"
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
systemctl --user daemon-reload
systemctl --user enable --now cti-crawl.timer
systemctl --user enable --now cti-weekly.timer

echo "[4/5] enabling lingering (lets the timers run without an open session)"
loginctl enable-linger "$USER" 2>/dev/null \
    || echo "  (enable-linger needs an admin; until then the timers run only while you are logged in)"

echo "[5/5] first dashboard build"
( cd "$DEST" && python3 build-dashboard.py )

echo
echo "Done. Open $DEST/dashboard.html in Tor Browser."
echo "The crawl runs every 2h (cti-crawl.timer); sources refresh weekly (cti-weekly.timer)."
echo "To run one crawl now:  XDG_RUNTIME_DIR=/run/user/\$(id -u) systemctl --user start cti-crawl.service"
