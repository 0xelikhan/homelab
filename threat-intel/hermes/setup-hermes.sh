#!/usr/bin/env bash
# Run as the hermes user inside CT 120. API keys arrive in ~/.setup-secrets
# (NAME='value' lines, mode 600), which this script deletes after reading.
set -uo pipefail
export LANG=C.UTF-8 PATH=$HOME/.local/bin:$PATH
SECRETS=$HOME/.setup-secrets
[ -f "$SECRETS" ] || { echo "missing $SECRETS"; exit 1; }
set -a; source "$SECRETS"; set +a
rm -f "$SECRETS"

REPO=$HOME/cti-skills
ENVF=$(hermes config env-path)

echo "── cti-skills repo ──────────────────────────────────────────"
if [ -d "$REPO/.git" ]; then git -C "$REPO" pull -q --ff-only; else git clone -q https://github.com/Liberty91LTD/cti-skills.git "$REPO"; fi
git -C "$REPO" log -1 --format='  cti-skills %h (%cd)' --date=short
rm -rf "$HOME/.hermes/skills/cti"
ln -sfn "$REPO/skills" "$HOME/.hermes/skills/cti"
echo "  skills linked: $(ls "$REPO/skills" | wc -l)"

echo "── Python deps for tools/clis ───────────────────────────────"
pip3 install --user --break-system-packages -q OTXv2 greynoise shodan censys-platform 2>&1 | tail -1
python3 -c "import OTXv2, greynoise, shodan; print('  imports ok')"

echo "── MITRE ATT&CK data ────────────────────────────────────────"
( cd "$REPO" && bash scripts/download-mitre.sh >/dev/null 2>&1 ) && ls -la "$REPO"/mitre-attack/*.json 2>/dev/null | awk '{print "  "$9" "$5" bytes"}'

echo "── .env (secrets, 600) ──────────────────────────────────────"
touch "$ENVF"; chmod 600 "$ENVF"
put() { grep -v -E "^$1=" "$ENVF" > "$ENVF.tmp" || true; printf "%s=%s\n" "$1" "$2" >> "$ENVF.tmp"; mv "$ENVF.tmp" "$ENVF"; chmod 600 "$ENVF"; }
put AZURE_FOUNDRY_BASE_URL "${OPENAI_BASE_URL%/}/openai/v1"
put AZURE_FOUNDRY_API_KEY  "$OPENAI_API_KEY"
put VIRUSTOTAL_API_KEY "$VIRUSTOTAL_KEY"
put URLSCAN_API_KEY    "$URLSCAN_KEY"
put ABUSEIPDB_API_KEY  "$ABUSEIPDB_KEY"
put GREYNOISE_API_KEY  "$GREYNOISE_KEY"
put OTX_API_KEY        "$OTX_KEY"
put CENSYS_PAT         "$CENSYS_API_KEY"
put MISP_URL           "https://10.10.10.21"
put OPENCTI_URL        "http://10.10.10.22:8080"
echo "  keys in .env: $(grep -c = "$ENVF")"

echo "── config ───────────────────────────────────────────────────"
hermes config set model.provider azure-foundry >/dev/null
hermes config set model.default "$AI_MODEL" >/dev/null
hermes config set model.base_url "${OPENAI_BASE_URL%/}/openai/v1" >/dev/null
hermes config set terminal.cwd "$REPO" >/dev/null
for k in model.provider model.default model.base_url terminal.cwd; do echo "  $k = $(hermes config get $k 2>/dev/null)"; done
