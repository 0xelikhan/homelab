#!/bin/sh
# Opened by the "Extract IOCs" desktop launcher. Paste text, Ctrl-D, get IOCs.
echo "=== IOC Extractor ==="
echo "Paste the leak-site / forum / chat text below, then press Ctrl-D:"
echo
python3 /home/user/Desktop/cti/extract-iocs.py -
echo
echo "Output: ~/Desktop/cti/iocs/iocs.csv (MISP) + iocs.stix.json (STIX 2.1)"
echo "Press Enter to close."
read x
