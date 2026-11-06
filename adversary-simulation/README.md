# Adversary Simulation

Group `attack` (`lab-profile attack start`): Kali, DC01, Metasploitable2.

## Kali

| Item | Value |
|---|---|
| VM | 107 `kali`, VLAN 30, 4 GB RAM, 120 GB disk |

Installed commands include msfconsole, netexec / crackmapexec, impacket, evil-winrm, bloodhound-python, responder, sliver, burpsuite, zaproxy, nuclei, httpx-toolkit, trufflehog, gophish, sigma-cli (Splunk / Elastic / Sysmon backends), pwsh.

Repos in `/opt`: AdversaryEmulation, adversary_emulation_library, Mythic, caldera, Havoc, PowerSploit, dnscat2, fireprox, MSOLSpray, Kansa, rita, SecLists, volatility3, zircolite, hayabusa-rules, sigma-rules, cti-skills, deepdarkCTI, cti-analysis-toolkit, automated-cti-triage, snf-core, tracehound, ThreatIntelDiscordBot, TLS-Scanner, threatest.

### SANS tools

Cloned into `/opt`, wrappers in `/usr/local/bin`.

| Command | Repo | What |
|---|---|---|
| `autocrack` | timbo05sec/autocrack | hashcat wrapper, automates wordlist/rule/mask runs |
| `digestive` | eric-conrad/digestive | dictionary cracker for HTTP Digest challenge/response |
| `dnssecchef` | dinosec/dnssecchef | DNS/DNSSEC interception proxy |
| `obscureV4` | dagonis/obscureV4 | obscure an IPv4 into 100+ formats that still connect (WAF/IDS bypass) |
| `powercat` | besimorhino/powercat | PowerShell netcat (dot-sourced function) |
| `deepblue` | sans-blue-team/DeepBlueCLI | event-log threat hunting. On Kali, `DeepBlue.py` (libevtx) parses evtx offline; full coverage is the `.ps1` on the Windows VMs |

`digestive`, `dnssecchef` and DeepBlueCLI's `DeepBlue.py` are Python 2.

## C2 frameworks

| C2 | Location | Start | Access |
|---|---|---|---|
| Sliver | `sliver-server` / `sliver-client` | `sliver-server` | local mTLS |
| Mythic | `/opt/Mythic` (Docker) | `sudo ./mythic-cli start` | `https://127.0.0.1:7443` |
| CALDERA | `/opt/caldera`, image `caldera:server` (Docker) | `sudo docker start caldera` | `http://127.0.0.1:9999` |
| Havoc | `/opt/Havoc`, teamserver `/opt/Havoc/havoc` | `./havoc server --profile profiles/havoc.yaotl -v` | teamserver + GUI client |

Mythic autostarts its stack on boot and holds 8888 (Jupyter) and 7000-7010, so CALDERA is
remapped: web on host 9999 (→8888), agents on 7110/7111/7112/8953. CALDERA login is generated in
`/opt/caldera/conf/local.yml`.

Havoc teamserver is built (`make ts-build`). The Qt client is not built — the Qt/boost download is
large over the slow Kali mirror. To finish Havoc later:
`sudo apt install -y cmake mingw-w64 qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5-dev qtdeclarative5-dev libboost-all-dev libspdlog-dev && cd /opt/Havoc && make client-build`
(mingw-w64 is also required for the teamserver to generate Windows demon payloads.)

## Pages

| Page | What |
|---|---|
| [metasploit](metasploit/README.md) | Metasploitable2 and web-01 exploitation |
| [ad-attacks](ad-attacks/README.md) | Kerberoasting, PtH, BloodHound against the lab domain |
