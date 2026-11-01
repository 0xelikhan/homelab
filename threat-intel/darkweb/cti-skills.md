# (C) cti-skills — skills inventory + source references

78 skills under `/skills`. Each `SKILL.md` has YAML frontmatter (`name`, `description`, `user-invocable`). Note: this is a defensive-analyst skills pack (API-lookup wrappers + analytic-tradecraft skills). Only `darkweb-collection` carries dark-web source lists.

## C.1 — Skill inventory (name — one-line summary)
**API reference skills (not user-invocable, retrieval refs):** `abuseipdb-api` — AbuseIPDB IP reputation/abuse reports. `censys-api` — Censys v2 host + cert data. `crowdstrike-api` — Falcon Intel (FQL, IOC/actor/report lookups, ATT&CK). `greynoise-api` — scanner/noise classification. `otx-api` — AlienVault OTX pulses. `reversinglabs-api` — Spectra Analyze (A1000) file/URL intel. `shodan-api` — host recon/ports/vulns. `urlscan-api` — URL submission/scan. `virustotal-api` — VT v3 file/IP/domain/URL. `mitre-attack` — local enterprise-attack.json query.

**Lookup skills (live retrieval/integration):** `lookup-abuseipdb`, `lookup-censys`, `lookup-crowdstrike`, `lookup-greynoise`, `lookup-misp` (two-way MISP), `lookup-opencti` (two-way OpenCTI), `lookup-otx`, `lookup-ransomwarelive` (ransomware.live PRO — 27k+ victims, 330+ groups), `lookup-reversinglabs`, `lookup-sentinel` (hunt own Sentinel workspace), `lookup-shodan`, `lookup-urlscan`, `lookup-virustotal`, `lookup-liberty91` (first-party Liberty91 platform, two-way).

**Investigation / workflow:** `cti-orchestrator` (default router), `ip-investigation`, `domain-investigation`, `url-investigation`, `hash-investigation`, `indicator-pivoting`, `ioc-enrichment-workflow`, `ioc-export` (CSV/STIX/OpenIOC/MISP), `malware-analysis`, `osint-methodology`, `cti-setup` (API-key config).

**Knowledge cells (self-updating threat domains):** `ransomware-ecosystem`, `initial-access-brokers`, `infostealers`, `carding-financial-fraud`, `phishing-social-engineering`, `supply-chain-threats`, `hacktivism`, `china-cyber-espionage`, `russia-cyber-espionage`, `iran-cyber-espionage`, `dprk-cyber-espionage`, `vulnerability-intelligence`, `threat-actor-profiling`, `campaign-tracking`.

**Analytic tradecraft / SAT:** `structured-analytic-techniques`, `ach`, `key-assumptions-check`, `devils-advocacy`, `quality-of-information-check`, `claim-extraction`, `source-assessment` (Admiralty), `source-provenance`, `confidence-levels`, `likelihood-language`, `tlp-guide` (TLP v2.0), `threat-assessment`, `writing-assessments`, `horizon-scanning`, `quality-control`.

**Detection engineering:** `sigma-writing`, `yara-writing`, `kql-writing`.

**Programme / process:** `intelligence-writing`, `intelligence-sharing` (ISAC/TAXII/MISP/STIX), `stix-bundle`, `pir-management`, `sops`, `stakeholder-management`, `maturity-assessment`, `control-coverage-mapping` (ATT&CK control mapping, 9,545 mappings), `cti-hyperloop`, `feedback-loops`.

**Collection:** `darkweb-collection` (see C.2).

## C.2 — Dark-web / Telegram / onion / source references found in skills

**`darkweb-collection`** is the only skill with substantive source lists. It explicitly "never visits a .onion address" and recommends a vendor-first posture. Contents:

- **CTI vendors named (access-methods.md matrix):** KELA, Flashpoint, Intel471, DarkOwl Vision, Recorded Future, Cybersixgill (Searchlight), Webz.io (Lunar/Dark Web API), SOCRadar, Hudson Rock (Cavalier — free tier), IntelligenceX (free ~50 queries/day), Constella.
- **Onion indexers / monitoring (used by scripts + passive-monitoring.md):** Ahmia (ahmia.fi), dark.fail (PGP-signed mirror list), IntelligenceX; ransomwatch, ransomlook.io, ransomware.live; HIBP, Constella, Hudson Rock free tier; tgstat.
- **references/forums.md — 35+ forums across 8 categories** (surface mirrors only; live .onion deliberately excluded, resolved at runtime via `onion_search.py`):
  1. Russian elite: Exploit (exploit.in), XSS (xss.pro), DamageLib, Verified, Maza, Crdclub, RAMP (seized Jan 2026), WWH-Club, Lolzteam (zelenka.guru), BHF (bestblackhatforum.com).
  2. English leak: BreachForums v1–v4, RaidForums, Cracked.io, Nulled.to, LeakBase, Exposed.vc, DarkForums (DARK4RMY), HackForums, Dread, Sinister.ly.
  3. Carding/fraud: Joker's Stash, UniCC, BriansClub, BidenCash, Russianmarket.to, B1ack's Stash, WWH-Club.
  4. Infostealer log marketplaces: Genesis Market, Russian Market, 2easy Shop, Exodus Marketplace.
  5. Exploit/0day: 0day.today, Exploit.in.
  6. Hacktivist boards: KillNet (Telegram-primary), Anonymous Sudan.
  7. Regional: 52pojie (I Love Cracking), Exchange Market (DeepMix), FREECITY, Indetectables, Ashiyane Forum, Warriors.to.
  8. Doxing overlap: Doxbin.
- **references/telegram-channels.md — 30+ channels across 6 categories**, each with @handle, status, affiliation, language, and a Tier-1 source citation (handles given without live t.me links to avoid phishing). Categories & notable entries:
  1. Ransomware official: LockBit 3.0 (@lockbitchannels, seized), LockBit APT (@LockBit_APT, banned), 8Base (@eightbase, seized), Medusa (@OSINT_without_borders, active), Snatch (@snatch_info), Bl00dy (@bl00dy_Ransomware_Gang), Kill Security (@k1llsec).
  2. IAB storefronts: BreachForums (@breachforums, seized), Jacuzzi/Baphchat (@jacuzzidf → @DarkForumsHub), DarkForums Hub (@DarkForumsHub).
  3. Infostealer shops: Moon Cloud, Observer Cloud, Daisy Cloud, Omega Cloud (handles "not confirmed"), LummaC2 Stealer (@LummaC2Stealer, seized), BidenCash CVV (seized).
  4. Hacktivist — pro-RU: NoName057(16) (@noname05716, @noname05716eng, @noname05716engver), CARR (@CyberArmyofRussia_Reborn), Z-Pentest/Z-Alliance (@ZAllianceRU), WE ARE KILLNET (@killnet_reservs), Killnet (@Killneto), IT Army of Russia (@itarmyofrussianews); pro-UA: IT Army of Ukraine (@itarmyofukraine2022); pro-Palestine/MENA: Dark Storm Team (@DarkStormTeams), RipperSec (@RipperSec), DragonForce Malaysia (@dragonforceio), Handala (@Handala_hack), Anonymous Sudan, DieNet (banned); mixed: Indian Cyber Force (@TeamIndianCyberForce).
  5. Breach aggregators: Handala backup (@Handala_backup), Snatch news (@snatch_news), BreachForums News (@BreachForumsNews), Team Underground (@UndergroundDataLeaks).
  6. Defender-run (safe-to-follow): vx-underground (@vxunderground), FalconFeeds (@falconfeeds), Cyber Threat Intelligence (@ctinow); plus CyberKnow (@Cyberknow20, X/Substack not Telegram).
- **Bundled scripts (scripts/):** `onion_search.py` (clearnet query of Ahmia/dark.fail/IntelligenceX), `telegram_monitor.py` (read-only Telethon monitor, requires `--i-understand-opsec`), `keyword_match.py` (local regex/keyword scanner over JSONL).
- Several knowledge-cell skills reference the same actors as prose (not source lists): `ransomware-ecosystem` (LockBit/ALPHV/RansomHub/Akira/Play/Qilin/Cl0p/Medusa), `hacktivism` (Killnet, NoName057(16), IT Army of Ukraine, Anonymous Sudan, RipperSec, CARR), `infostealers` (LummaC2, RedLine, Vidar, Stealc, Raccoon, Rhadamanthys; Russian Market, Genesis successors, BidenCash, Hudson Rock corpus), `carding-financial-fraud` (BidenCash, Brian's Club, Russianmarket, B1ack's Stash), `initial-access-brokers`. These are analytic cells, not source directories.

---

## Local raw copies (scratchpad)
All deepdarkCTI raw files saved under: `C:\Users\huqta\AppData\Local\Temp\claude\C--Users-huqta-homelab\c2d95e91-9871-472b-86ca-782aed5a42ea\scratchpad\ddcti\` (21 .md files). Full darkweb-collection text (SKILL.md + telegram-channels.md + forums.md) saved at `C:\Users\huqta\.claude\projects\C--Users-huqta-homelab\c2d95e91-9871-472b-86ca-782aed5a42ea\tool-results\bpciy95a6.txt`.