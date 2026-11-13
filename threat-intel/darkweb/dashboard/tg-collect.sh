#!/bin/sh
# Telegram sample collection via telegram-tracker (github.com/estebanpdl/telegram-tracker).
# Runs ONLY on this isolated, Tor-forced Whonix box with a THROWAWAY account. It no-ops
# until an authorised session + a non-empty channel list exist, so the crawl pipeline runs
# fine before the account is set up. Downloads ONLY document attachments (the sample files)
# and moves them to ~/tg-intake for triage.py. Nothing is executed.
TGT="$HOME/telegram-tracker"
BATCH="$HOME/tg-channels.txt"
[ -d "$TGT" ] || exit 0
[ -s "$BATCH" ] || exit 0
# require an authorised session or saved credentials (set up by `auth login`); else no-op
if ! ls "$HOME"/.telegram-tracker/*.session "$TGT"/*.session "$HOME"/.telegram-tracker/credentials.json >/dev/null 2>&1; then
    exit 0
fi
cd "$TGT" || exit 0
python3 main.py collect --batch-file "$BATCH" --output "$HOME/tg-out" >/tmp/tgcollect.log 2>&1
python3 main.py download-media --output "$HOME/tg-out" --media-types file >>/tmp/tgcollect.log 2>&1
mkdir -p "$HOME/tg-intake"
# flatten the downloaded document files into the intake dir for triage
find "$HOME/tg-out/downloaded-media" -type f -path '*/files/*' -exec mv -t "$HOME/tg-intake" {} + 2>/dev/null
