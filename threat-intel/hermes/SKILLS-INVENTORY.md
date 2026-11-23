# Hermes CTI Skills: Inventory, Wiring, and Report Design

All 78 Liberty91 cti-skills, what each one does, and exactly how this deployment uses it. Pairs with the ranking doc (`cti-skills-deep-dive-and-ranking.md` at the repo root). This file records the state after the 2026-11-12 consolidation.

## The one fact that frames everything

The two brief skills (`cti-daily-brief`, `cti-weekly-roundup`) are themselves orchestrators. They already route findings through most of the 78 by calling `/skill-name` inline. The `"skills"` array in `jobs.json` is only a preload hint, not the working set. So the deployment was never running "3 of 78"; it was running most of the pack. The work on 2026-11-12 did not add skills. It consolidated 15 of them into 2 and tightened the briefs, so the same depth loads less context per run.

## Status legend

- **Wired**: named in the daily brief, weekly roundup, or fin-flash, and runnable today.
- **Merged to CE**: now loaded through `/cyber-espionage`, which loads only the one cell a finding needs.
- **Merged to AR**: now loaded through `/analytic-rigor`, the lightweight tradecraft layer.
- **On-demand**: symlinked and callable (`/skill` or `hermes -z "..." --skills <name>`), not in a scheduled job.
- **Parked**: kept on disk as a fallback reference, not loaded in a normal run.
- **Excluded**: not used by the bot, because it has no key or belongs to another system.

## What changed on 2026-11-12

1. Built `/cyber-espionage`: one skill holding 8 knowledge cells (China, Russia, Iran, DPRK, phishing, supply-chain, hacktivism, horizon) verbatim in `references/`, with a thin router that loads only the cell a finding needs. All information retained, one cell loaded instead of eight.
2. Built `/analytic-rigor`: a compact synthesis of 7 tradecraft skills (claim grading, the confidence ceiling, key-assumptions check, ACH, devil's advocacy, SAT selection, assessment structures), applied to every judgement. The full standalone skills remain for deep interactive products.
3. Rewired both briefs to call `/cyber-espionage` and `/analytic-rigor` in place of the 15 individual references.
4. Salvaged the one genuinely reusable part of the redundant set (claim-extraction's atomic-claim method) into `/analytic-rigor`.

---

## Group 1: Orchestration, setup, and program

| Skill | What it does | Status |
|---|---|---|
| cti-orchestrator | Routes an ad-hoc question or finding to the right skill | On-demand (front door for interactive bot use; briefs name skills directly) |
| sops | Daily and weekly briefing and triage runbooks | Wired (both briefs follow it) |
| quality-control | Final product QC checklist and schema validation | Wired (briefs run it before saving) |
| feedback-loops | Tracks which feeds produce signal vs noise over time | Wired (weekly source-quality table) |
| pir-management | Keeps the PIR set (`pirs.md`) sharp | Parked (briefs read `pirs.md` directly; management is periodic setup) |
| cti-setup | One-time API-key configuration helper | Excluded (keys already set, job done) |
| stakeholder-management | Sets audience and output format | Excluded (one-time setup) |
| maturity-assessment | Program maturity benchmark | Excluded (no per-run value) |
| cti-hyperloop | Strategic / operational / tactical doctrine | Excluded (reference removed from the weekly this session; a plain instruction replaces it) |

## Group 2: Enrichment and lookups (live keys)

| Skill | What it does | Status |
|---|---|---|
| ioc-enrichment-workflow | Routes each IOC through the live lookups and merges one record per indicator | Wired (mandatory enrichment step) |
| lookup-virustotal | VT reputation on IP, domain, hash, URL | Wired |
| lookup-otx | OTX pulse membership: is this part of a known campaign | Wired |
| lookup-abuseipdb | IP abuse-confidence score | Wired |
| lookup-urlscan | URL and domain detonation-lite | Wired |
| lookup-misp | Two-way: dedupe IOCs against MISP, publish findings back | Wired |
| lookup-opencti | Two-way against the OpenCTI knowledge base | Wired |
| indicator-pivoting | Expands one IOC into a related cluster | Wired |
| ip-investigation | VT + AbuseIPDB + GreyNoise + OTX chain on an IP | Wired (GreyNoise leg skipped) |
| domain-investigation | VT + URLScan + OTX chain on a domain | Wired |
| url-investigation | URLScan + VT + OTX chain on a URL | Wired |
| hash-investigation | VT + OTX on a file hash | Wired (light use; the Whonix pipeline leads on deep hash triage) |
| ioc-export | Formats vetted IOCs for dissemination | Wired (export step) |
| lookup-ransomwarelive | Queries ransomware.live | On-demand (the collector already ingests ransomware.live into `intel.db`) |
| lookup-greynoise | Mass-scanner noise filter | Excluded (brief says do not run; free tier too small) |

## Group 3: API reference docs

| Skill | What it does | Status |
|---|---|---|
| virustotal-api | VT API v3 endpoint reference | Parked (fallback when the CLI lacks an endpoint) |
| otx-api | OTX API reference | Parked |
| urlscan-api | URLScan API reference | Parked |
| abuseipdb-api | AbuseIPDB API reference | Parked |
| greynoise-api | GreyNoise API reference | Parked (GreyNoise not run here) |
| shodan-api | Shodan API reference | Excluded (no key) |
| censys-api | Censys API reference | Excluded (no key) |
| crowdstrike-api | CrowdStrike API reference | Excluded (no key or subscription) |
| reversinglabs-api | ReversingLabs API reference | Excluded (no key) |

## Group 4: Lookups with no key or no backend

| Skill | What it does | Status |
|---|---|---|
| lookup-shodan | Shodan host/exposure lookup | Excluded (no key; the missing leg in ip/domain chains) |
| lookup-censys | Censys host lookup | Excluded (no key; free tier 250/month) |
| lookup-crowdstrike | CrowdStrike Falcon Intelligence actor/TTP lookup | Excluded (no key; paid sub) |
| lookup-reversinglabs | ReversingLabs file reputation | Excluded (no key; pipeline's job) |
| lookup-sentinel | Microsoft Sentinel query | Excluded (no Sentinel workspace) |
| lookup-liberty91 | Liberty91 platform lookup | Excluded (platform not run) |

## Group 5: Threat knowledge cells

| Skill | What it does | Status |
|---|---|---|
| ransomware-ecosystem | Ransomware groups, affiliates, leak-site patterns | Wired (all three jobs; backbone of the financial focus) |
| infostealers | Stealer families and the credential-exposure pipeline | Wired (kept separate: financial priority) |
| carding-financial-fraud | Carding, BIN fraud, financial-fraud ecosystem | Wired (kept separate: financial priority) |
| initial-access-brokers | IAB market: how victims are accessed before ransomware | Wired (kept separate: upstream context) |
| threat-actor-profiling | Structured canonical actor profiles | Wired |
| campaign-tracking | Clusters multiple incidents into one campaign (timeline, victimology, Diamond) | Wired |
| china-cyber-espionage | PRC state-nexus cell (APT41, Volt/Salt/Silk Typhoon, Mustang Panda, UNC5221) | Merged to CE |
| russia-cyber-espionage | Russian state cell (APT28/29, Sandworm, Turla, Gamaredon, GRU fronts) | Merged to CE |
| iran-cyber-espionage | Iranian cell (APT35/42, MuddyWater, OilRig, Void Manticore, CyberAv3ngers) | Merged to CE |
| dprk-cyber-espionage | DPRK cell (Lazarus, BlueNoroff, Kimsuky, TraderTraitor, IT-worker scheme) | Merged to CE (the top-value cell for finance) |
| phishing-social-engineering | Phishing, BEC, AiTM, ClickFix, quishing, PhaaS | Merged to CE |
| supply-chain-threats | Vendor, package, CI/CD, and update-infrastructure compromise | Merged to CE |
| hacktivism | DDoS-claiming groups, pro-state OT tampering fronts | Merged to CE |
| horizon-scanning | Weak-signal scanning and emerging-threat scenarios | Merged to CE (weekly look-ahead) |

## Group 6: Analytic tradecraft

| Skill | What it does | Status |
|---|---|---|
| quality-of-information-check | CIA-primer source and claim grading with hard caps | Merged to AR |
| claim-extraction | Splits a source into atomic, typed, sentence-anchored claims | Merged to AR (its method is section 1 of analytic-rigor) |
| key-assumptions-check | Surfaces and tests the assumptions under a judgement | Merged to AR |
| ach | Analysis of Competing Hypotheses for contested attribution | Merged to AR |
| devils-advocacy | Builds the strongest case that a lead judgement is wrong | Merged to AR |
| structured-analytic-techniques | Selector that points to the right technique | Merged to AR (escalation pointer) |
| threat-assessment | Intent + Capability + Opportunity = Threat Level | Merged to AR |
| writing-assessments | Threat, risk, and vulnerability assessment templates | Merged to AR |

## Group 7: Source and confidence rigor (kept separate)

| Skill | What it does | Status |
|---|---|---|
| source-assessment | Grades source reliability (Admiralty A-F) | Wired |
| source-provenance | Traces a claim to its primary source and flags rewrites | Wired |
| confidence-levels | Calibrates low / moderate / high | Wired |
| likelihood-language | Fixed ICD 203 probability words | Wired |
| tlp-guide | TLP marking as a release gate | Wired |
| intelligence-writing | BLUF, active voice, clean sourcing | Wired |

## Group 8: ATT&CK and vulnerabilities

| Skill | What it does | Status |
|---|---|---|
| mitre-attack | Maps behaviour to ATT&CK technique IDs | Wired (all brief jobs) |
| vulnerability-intelligence | Turns a CVE into a patch call (severity, exploitation, action) | Wired (pairs with `cve-status` for KEV + EPSS) |

## Group 9: Detection and control coverage

| Skill | What it does | Status |
|---|---|---|
| control-coverage-mapping | Maps the day's techniques against the lab's Wazuh coverage | Wired (detection section) |
| sigma-writing | Drafts Sigma rules | Wired, low value (drafts only; no deploy target behind the bot) |
| yara-writing | Drafts YARA rules | Wired, low value (overlaps the Whonix triage pipeline, which owns YARA) |
| kql-writing | Drafts KQL | Wired, low value (no Sentinel/Defender behind the bot) |
| malware-analysis | Deeper behavioural malware review | Wired, low value (the Whonix static pipeline owns this) |

## Group 10: Collection and sharing

| Skill | What it does | Status |
|---|---|---|
| osint-methodology | OSINT collection method and observe-only handling of leak/Telegram sources | Wired (collection guidance; overlaps the collector) |
| darkweb-collection | Observe-only dark-web handling rules | Wired (collection guidance; overlaps the dark-web pipeline) |
| stix-bundle | STIX 2.1 export for MISP/OpenCTI | Wired (optional export step) |
| intelligence-sharing | ISAC/TAXII/TLP dissemination guidance | Parked (overlaps tlp-guide; the bot already ships to Telegram and feeds MISP) |

---

## Salvage: the 9 redundant skills

The question was whether the redundant skills held anything worth keeping. The answer: most of their value is already wired into the briefs, so there was little to extract. The specifics:

- **claim-extraction**: worth keeping. Its atomic-claim method (split a source into 5 to 12 typed claims, each anchored to a verbatim sentence) is the step that makes grading checkable. Folded into `/analytic-rigor` section 1, so the briefs get it without loading the standalone.
- **virustotal-api, otx-api, urlscan-api, abuseipdb-api, greynoise-api**: nothing to extract. The briefs already cite them correctly as the fallback API reference when a CLI lacks an endpoint. Left Parked.
- **osint-methodology**: the one useful part, observe-only handling of leak and Telegram sources, is already referenced in the briefs' collection step. Nothing to move.
- **intelligence-sharing**: fully covered by tlp-guide plus the existing Telegram and MISP paths. Nothing to extract; left Parked.
- **hash-investigation**: fine as the light VT/OTX reputation step the briefs already use. The rule the bot should keep is not to lead on hashes, which is the Whonix pipeline's job. No change needed.

Net: one method salvaged (claim-extraction into analytic-rigor), the rest already positioned correctly.

---

## How the reports are built to read well and carry everything

The daily brief and weekly roundup are ordered so a reader gets the decision first and the evidence underneath. The structure, unchanged in substance by this session:

**Daily brief order**: Bottom line (3 to 5 items with the so-what) → By PIR (each item graded, ATT&CK-mapped, enriched, linked) → Threat actors and campaigns → Exploited vulnerabilities (KEV and EPSS per CVE, new-to-KEV first) → Ransomware (financial-sector victims first) → Detections (coverage, then drafted rules) → Intelligence gaps and next collection → Sources and ratings.

**Weekly roundup order**: Bottom line → Ransomware (financial victims table first) → Exploited vulnerabilities → ATT&CK trend table (this week vs the Red Canary baseline: rising / steady / quiet, with lab coverage) → Threat actors and campaigns → Strategic look-ahead → Detections → Source quality → Gaps → Sources.

What makes them rich rather than thin, and where the consolidated skills feed in:

- **Every IOC is enriched, not just named.** `/ioc-enrichment-workflow` plus the live lookups attach a VT ratio, AbuseIPDB score, and OTX pulse count to each indicator. A brief built from titles alone is treated as incomplete.
- **Every claim is graded.** `/analytic-rigor` resolves each source to its originator, grades it, and caps a judgement at its weakest load-bearing claim, with an Admiralty rating on every line. Confidence words are calibrated by `/confidence-levels` and `/likelihood-language`, never swapped for numbers.
- **Actor and threat-type context is deep but cheap.** `/cyber-espionage` loads only the one cell a finding touches, so a DPRK crypto item pulls the full DPRK knowledge base without dragging in seven other cells.
- **Vulnerabilities are decisions.** `/vulnerability-intelligence` plus `cve-status` give KEV status, EPSS, and an action per CVE.
- **Hard judgements get stress-tested.** For the few high-impact or ambiguous calls, `/analytic-rigor` runs a key-assumptions check, ACH, and a devil's-advocate pass before release.
- **Everything carries a TLP mark** via `/tlp-guide`, since the briefs leave the lab.

The Telegram message stays a short teaser (under 900 characters: bottom line, urgent actions, new KEV, financial ransomware victims) with the full brief attached as a file, so the chat is scannable and the depth is one tap away.

### Flagged for a later decision

The briefs still reference `yara-writing`, `kql-writing`, `malware-analysis`, `darkweb-collection`, and `lookup-ransomwarelive`, which are low value for a Telegram product (no deploy target, or owned by the Whonix pipeline and the collector). They were left in place because this session's scope was to consolidate, not to strip. Removing them from the briefs is a clean, separate cleanup if you want the runs leaner.

---

## Hermes interface

Hermes has no web UI. Its interface is the Telegram chat it is paired to, plus a `hermes` CLI on the box for administration (`hermes cron list|run`, `hermes pairing`, `hermes gateway status|restart`). On-demand skills are reached two ways: message the bot in Telegram, or run `hermes -z "<question>" --skills <name>` on the box. The dashboards you have (the dark-web board) belong to the Whonix pipeline, not to Hermes.
