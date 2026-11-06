#!/bin/sh
# Optional: offline multilingual translation for the crawler (Argos Translate).
#
# The crawler works WITHOUT this - it detects malware context in English, Russian
# and a set of CJK/Arabic/Farsi keywords on its own. This step adds neural
# translation so a non-English page whose wording is NOT in those keyword lists is
# translated to English before scoring, instead of being dropped. Everything runs
# locally on CPU; nothing is ever sent to a cloud translator.
#
# Models are large (~100 MB each) and download slowly over Tor, so this is a
# separate opt-in script rather than part of the fast-path install. Run it once and
# leave it; it is non-fatal and self-verifying - whatever installs cleanly is what
# the crawler will use.
#   sh install-translation.sh
set -e
LANGS="ru zh ko ar fa es fr"

echo "[1/3] installing argostranslate (CPU-only torch, no CUDA)"
pip3 install --user --break-system-packages \
     --index-url https://download.pytorch.org/whl/cpu torch >/dev/null 2>&1 \
     || echo "  (torch install skipped/failed - argos may still pull a default build)"
pip3 install --user --break-system-packages argostranslate >/dev/null

echo "[2/3] downloading <lang>->en packages over Tor (best-effort, per language)"
python3 - "$LANGS" <<'PY'
import sys
import argostranslate.package as P
try:
    P.update_package_index()
except Exception as e:
    print("  package index refresh failed:", str(e)[:70]); sys.exit(0)
avail = P.get_available_packages()
for code in sys.argv[1].split():
    pk = next((p for p in avail if p.from_code == code and p.to_code == "en"), None)
    if not pk:
        print("  %s->en: not in index" % code); continue
    try:
        P.install_from_path(pk.download())
        print("  %s->en: installed" % code)
    except Exception as e:
        print("  %s->en: FAILED (%s)" % (code, str(e)[:60]))
PY

echo "[3/3] verifying which pairs actually translate (a package can install but ship"
echo "      a truncated tokenizer; only the ones printed OK below will be used)"
python3 - <<'PY'
import argostranslate.translate as at
L = {l.code: l for l in at.get_installed_languages()}
en = L.get("en")
probe = {"ru": "червь", "zh": "蠕虫",
         "ko": "웜", "ar": "برمجية",
         "fa": "باج‌افزار",
         "es": "troyano", "fr": "maliciel"}
for c, w in probe.items():
    l = L.get(c)
    if not l or not en:
        print("  %s: not installed" % c); continue
    try:
        t = l.get_translation(en)
        print("  %s: OK -> %r" % (c, (t.translate(w) if t else None)[:30]))
    except Exception as e:
        print("  %s: BROKEN (%s)" % (c, str(e)[:55]))
PY
echo
echo "Done. The crawler auto-detects installed packages at run time - no config needed."
echo "Any pair printed BROKEN shipped a bad tokenizer; re-run to retry its download."
