# Adversary Simulation

Group `attack` (`lab-profile attack start`): Kali, DC01, Metasploitable2.

## Kali

| Item | Value |
|---|---|
| VM | 107 `kali`, VLAN 30, 4 GB RAM, 120 GB disk |

Installed commands include msfconsole, netexec / crackmapexec, impacket, evil-winrm, bloodhound-python, responder, sliver, burpsuite, zaproxy, nuclei, httpx-toolkit, trufflehog, gophish, sigma-cli (Splunk / Elastic / Sysmon backends), pwsh.

Repos in `/opt`: AdversaryEmulation, adversary_emulation_library, Mythic, PowerSploit, dnscat2, fireprox, MSOLSpray, Kansa, rita, SecLists, volatility3, zircolite, hayabusa-rules, sigma-rules, cti-skills, deepdarkCTI, cti-analysis-toolkit, automated-cti-triage, snf-core, tracehound, ThreatIntelDiscordBot, TLS-Scanner, threatest.

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

## Pages

| Page | What |
|---|---|
| [metasploit](metasploit/README.md) | Metasploitable2 and web-01 exploitation |
| [ad-attacks](ad-attacks/README.md) | Kerberoasting, PtH, BloodHound against the lab domain |
