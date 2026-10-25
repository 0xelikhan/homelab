# Adversary Simulation

Group `attack` (`lab-profile attack start`): Kali, DC01, Metasploitable2.

## Kali

| Item | Value |
|---|---|
| VM | 107 `kali`, VLAN 30, 4 GB RAM, 120 GB disk |

Installed commands include msfconsole, netexec / crackmapexec, impacket, evil-winrm, bloodhound-python, responder, sliver, burpsuite, zaproxy, nuclei, httpx-toolkit, trufflehog, gophish, sigma-cli (Splunk / Elastic / Sysmon backends), pwsh.

Repos in `/opt`: AdversaryEmulation, adversary_emulation_library, Mythic, PowerSploit, dnscat2, fireprox, MSOLSpray, Kansa, rita, SecLists, volatility3, zircolite, hayabusa-rules, sigma-rules, cti-skills, deepdarkCTI, cti-analysis-toolkit, automated-cti-triage, snf-core, tracehound, ThreatIntelDiscordBot, TLS-Scanner, threatest.

## Pages

| Page | What |
|---|---|
| [metasploit](metasploit/README.md) | Metasploitable2 and web-01 exploitation |
| [ad-attacks](ad-attacks/README.md) | Kerberoasting, PtH, BloodHound against the lab domain |
