# Liberty91 CTI Skills: Deep-Dive and Ranking for the Hermes Telegram Bot

Scope: all 78 skills from the Liberty91LTD cti-skills pack, cloned on the Hermes box at `/home/hermes/cti-skills/skills` and symlinked into the agent at `~/.hermes/skills/cti`. Part 1 explains what each one actually does. Part 2 ranks all 78 by how much they help your specific setup: the Hermes Telegram bot (LXC 120) running daily-cti-brief (07:00), weekly-cti-roundup (Mon 08:00), and fin-ransomware-flash (every 2h on new financial-sector ransomware victims).

Setup facts the ranking is grounded in:
- Live API keys on the box: VirusTotal, URLScan, AbuseIPDB, GreyNoise, OTX, MISP, OpenCTI, Cortex.
- No key, so dead weight today: Censys, Shodan, CrowdStrike, ReversingLabs, Sentinel, ransomware.live API, Liberty91 platform.
- Already wired into the scheduled jobs: source-assessment, mitre-attack, ransomware-ecosystem (plus the two custom local skills cti-daily-brief and cti-weekly-roundup, which are not part of the 78).
- The collector already pulls ransomware.live, CISA KEV, deepdarkCTI, and Telegram channels into `intel.db`, and the bot has `cve-status` and `misp-recent` tools.
- The static malware triage pipeline (capa, YARA, MalwareBazaar) runs on the separate Whonix box, not in Hermes. Detection-engineering and malware skills help that workflow, not this bot.

---

# Part 1: Grouped Deep-Dive

## Orchestration and setup

**cti-orchestrator** is the front door for any request that does not name a specific skill. It reads the shape of the input (a bare IP, a domain, a hash, a URL, an actor name, or a pasted article URL) and routes to the matching investigation, profiling, enrichment, or provenance skill, then automatically layers the rigor skills (source rating, TLP, confidence, likelihood) onto whatever comes back. Its value is interactive: when you message the bot ad hoc with "look at this indicator," it picks the right chain. It adds little to the three scheduled jobs because those already name their skills explicitly.

**cti-setup** is a configuration helper that walks you through writing API keys into the pack's environment without hand-editing a shell script. It handles first-time setup, adding one key at a time, and verifying that a configured key actually authenticates. It is a one-time operational tool. On your box the keys are already set, so it has done its job.

**cti-hyperloop** is doctrine, not tooling. It describes Liberty91's model of the intelligence lifecycle as a fast feedback loop across strategic, operational, and tactical levels. It is reference reading that shapes how you structure a program. It produces no output and chains to nothing.

## Investigation chains (by IOC type)

**ip-investigation** takes a single IPv4 or IPv6 address and fans out in parallel to VirusTotal, Shodan, AbuseIPDB, GreyNoise, OTX, and optionally Censys, then consolidates the results into one picture (reputation, open services, abuse history, scanner-noise classification, community pulses) and surfaces the best follow-up IOCs to pivot on. On your box the VT, AbuseIPDB, GreyNoise, and OTX legs are live; the Shodan and Censys legs return nothing because those keys are unset, so you get a mostly-complete host picture minus the port and service recon. It is invoked by cti-orchestrator when the target is an IP and feeds indicator-pivoting.

**domain-investigation** takes a domain or hostname and chains VirusTotal, URLScan (searching existing scans), Shodan (DNS resolve plus host), OTX, and a ransomware.live victim-status sweep, with Censys optional. It returns reputation, DNS resolution, a hosting fingerprint, whether the domain shows up as a ransomware victim, and pivot candidates. VT, URLScan, and OTX are live; the Shodan leg and the ransomware.live API leg are keyless, though the collector already holds ransomware.live victim data separately. Invoked by cti-orchestrator for domains.

**url-investigation** submits a URL to URLScan (unlisted by default), cross-references VirusTotal and OTX, and extracts the parent domain and resolved IP for follow-on investigation. It returns a verdict, the redirect chain, the infrastructure the page contacted, and a screenshot link. All three of its backends (URLScan, VT, OTX) are live on your box, so this chain works end to end. Invoked by cti-orchestrator for URLs.

**hash-investigation** takes an MD5, SHA-1, or SHA-256 and chains VirusTotal and OTX, and can escalate to malware-analysis for a novel sample. It returns detection signals, the malware family, behavioral tags, and pivot candidates such as communicating IPs and dropped files. VT and OTX are live, so it works, but hash triage is mostly the job of your separate static pipeline on the Whonix box, so it duplicates capability the bot does not need to lead on.

## Lookup connectors (single-source retrieval)

**lookup-virustotal** is the atomic VT call behind the investigation chains. Given an IP, domain, hash, or URL it returns the detection ratio, verdict, community score, and key findings, and nothing more (it retrieves, it does not interpret). Live on your box. This is the single broadest enrichment source you have, because it covers all four IOC types.

**lookup-otx** checks an IP, domain, hash, or URL against AlienVault OTX community pulses and returns pulse count, the key pulses, tags, related indicators, and passive DNS. Live. It is the community-context layer that tells you whether an indicator is already part of a reported campaign.

**lookup-abuseipdb** is IP-only. It returns the abuse-confidence score, total report count, number of distinct reporters, and the usage type (hosting, ISP, and so on). Live. It is the fastest way to separate a noisy abusive IP from a clean one in a brief.

**lookup-greynoise** is IP-only and classifies whether an address is internet background scanner noise versus targeted activity, with benign/malicious/unknown flags and an actor name when known. Live. Its real worth to a brief is negative filtering: it stops the bot from elevating a mass-scanning IP as though it were a targeted threat.

**lookup-urlscan** submits a URL for a live scan and retrieves the result, or searches existing scans for a domain. It returns the verdict, the final URL after redirects, the resolved IP, contacted domains and IPs, and a screenshot URL. Live. It is the detonation-lite step for suspicious links.

**lookup-misp** is a two-way connector to your MISP instance. It queries existing events, attributes, and objects, and it can push new intel back (add attributes, create an event, upload a STIX 2 bundle). Live (reads `$MISP_URL` and `$MISP_API_KEY`). Because your collector and the `misp-recent` tool already revolve around MISP, this skill is how the agent checks whether an indicator is already known to your sharing community and how it writes findings back.

**lookup-opencti** is the two-way connector to your OpenCTI knowledge base. It queries whether an IOC or entity is already known and pushes new intel (indicators, observables, labels, TLP markings, relationships, STIX 2.1 import). Live (reads `$OPENCTI_URL` and `$OPENCTI_TOKEN`). Same role as lookup-misp but against OpenCTI: dedup on the way in, publish on the way out.

**lookup-censys** does deep host and certificate recon for an IP, or runs a Censys search, returning services, TLS certs, ASN, and location. No key on your box, and even with one the free tier is capped at 250 queries a month. Dead weight today.

**lookup-shodan** does host recon for an IP or domain (open ports, services, banners, OS guess, known CVEs), resolving DNS first for domains. No key. This is the missing leg inside ip-investigation and domain-investigation, so its absence degrades those chains, but the skill itself cannot run.

**lookup-crowdstrike** pulls Falcon Intelligence on an indicator (malicious confidence, linked actors, malware families, reports) or on an adversary (profile, origin and target search, ATT&CK TTPs, finished reports). No key and it needs a paid Falcon Intelligence subscription. Dead weight.

**lookup-reversinglabs** returns authoritative file classification, threat name, ATT&CK mapping, and dynamic-analysis results from ReversingLabs Spectra Analyze, plus network reputation for URLs/domains/IPs. No key, and it is aimed at deep malware enrichment, which is your separate triage pipeline's job. Dead weight for the bot.

**lookup-sentinel** hunts your own Microsoft Sentinel workspace for IOC hits and ATT&CK behaviors, discovering available tables first and only generating KQL for tables that exist. No key and you run no Sentinel workspace behind this bot. Dead weight.

**lookup-ransomwarelive** checks whether an org or domain has been claimed by a ransomware group, profiles a group (TTPs, leak-site infra, IOCs, YARA), or aggregates victim claims by country, sector, and timeframe, backed by ransomware.live's 27k-plus victim scrapes. Reads `$RANSOMWARE_LIVE`, which is unset, and in any case your collector already ingests ransomware.live into `intel.db`, so the data path is covered elsewhere. Low value as a skill.

**lookup-liberty91** is the first-party, two-way integration with the Liberty91 platform: deduplicated threat events with Admiralty ratings, whether an IOC is already known to your account, the canonical threat library, alert matches, and push operations (ingest a report, generate an intel package). Reads `$LIBERTY91_API_KEY`, which is unset, and you do not run the platform. Dead weight.

## Raw API references (documentation, not actions)

These seven are reference docs for the underlying services. They describe endpoints, auth, and query syntax. They do not perform lookups themselves; the matching lookup-\* skill wraps the same API into an action. They matter only when you are building or debugging a call by hand.

**virustotal-api** documents VT API v3 file, IP, domain, and URL endpoints. Reference for the live VT integration.

**urlscan-api** documents URLScan.io submission, scanning, and result retrieval. Reference for the live URLScan integration.

**abuseipdb-api** documents the AbuseIPDB reputation and report endpoints. Reference for the live AbuseIPDB integration.

**greynoise-api** documents the GreyNoise scanner-classification endpoints. Reference for the live GreyNoise integration.

**otx-api** documents the AlienVault OTX pulse and indicator endpoints. Reference for the live OTX integration.

**censys-api** documents Censys API v2 host and certificate endpoints. Reference for a service you have no key for.

**shodan-api** documents the Shodan host, port, and vulnerability endpoints. Reference for a service you have no key for.

**crowdstrike-api** documents the Falcon Intelligence API (OAuth2, Falcon Query Language, IOC and actor entities, reports, ATT&CK mappings). Reference for a service you have no key and no subscription for.

**reversinglabs-api** documents the ReversingLabs Spectra Analyze (A1000) API (hash classification, dynamic analysis, network reputation, YARA, container relationships). Reference for a service you have no key for and that targets the separate triage pipeline.

## Enrichment and pivoting

**ioc-enrichment-workflow** takes a batch of raw IOCs and routes each one by type to the right lookup-\* skills, optionally correlates against MISP, and synthesizes a single enrichment record per indicator. Inputs are raw indicators, output is a per-indicator record ready for triage or for pushing into a sharing platform. It is the orchestration layer that turns your live keys (VT, OTX, AbuseIPDB, GreyNoise, URLScan, MISP) into one clean result instead of five scattered ones. This is the single biggest upgrade available to the daily brief: wire it in and IOCs arrive enriched instead of bare.

**indicator-pivoting** is the methodology for using one known indicator to discover related infrastructure across the IOC graph. It is a decision tree keyed by indicator type, with the concrete lookup-\* command to run for each pivot, a worked multi-hop example, and pivot-quality scoring, then it routes the results into the rigor pipeline. It takes one seed IOC and produces an expanded cluster. It depends on the live lookups to actually walk the graph, so it works on your box, but it is more an interactive investigative tool than a scheduled-brief step.

**ioc-export** handles output formatting: CSV, STIX 2.1, OpenIOC, and MISP, including format conversion and packaging, and it carries per-claim evidence grades (access level and claim support) from quality-of-information-check into each format (STIX confidence fields, MISP attribute tags). Input is a set of graded IOCs, output is a shareable file in the chosen format. Useful when you are disseminating, not when you are briefing.

## Analytic tradecraft and structured analytic techniques

**structured-analytic-techniques** is the index and selector for the SAT family. You ask "which technique fits this problem" and it points you to quality-of-information-check, ACH, key-assumptions-check, devils-advocacy, and the rest, with quality-of-information-check set as the default first step of any diagnostic run. It is a meta-skill that organizes the others.

**ach** (Analysis of Competing Hypotheses) evaluates multiple explanations against a matrix of evidence, built for ambiguous attribution or several plausible scenarios. It prefers graded evidence from quality-of-information-check and will run that skill first on raw input; if you force it onto ungraded evidence it says so, runs unweighted, and caps the result at Moderate confidence. Input is a claim set and hypotheses, output is a ranked hypothesis matrix with the evidence that most discriminates between them. Heavy, and best used interactively on a hard attribution call, not inside a daily brief.

**key-assumptions-check** surfaces the assumptions underneath an analytic judgment and tests whether each still holds. It is the standard SAT to run before publishing a high-impact assessment. Input is a draft judgment, output is the list of load-bearing assumptions flagged by how fragile they are. Most valuable on the weekly roundup, where a wrong assumption is costly, less so on the fast daily brief.

**devils-advocacy** takes your own lead judgment and builds the strongest case that it is wrong, to stress-test an assessment before release. It is a contrarian technique (it does not model what an adversary would do next, which would be red-team analysis). Interactive by nature; you invoke it on a specific judgment you want challenged.

**confidence-levels** assigns a named confidence level (High, Moderate, Low) with 0-to-100 score ranges aligned to STIX, enforcing the rule that confidence cannot exceed what the weakest load-bearing claim supports. Input is a judgment plus its evidence, output is the rated level with the cap applied. It needs no key, it is cheap to run, and every judgment the bot publishes should carry it. One of the highest-leverage rigor skills for the briefs.

**likelihood-language** standardizes forward-looking probability phrasing ("likely," "very likely," and so on) across products so the same words mean the same odds every time. Input is a forecast statement, output is the statement with calibrated probability language. No key, cheap, and it directly tightens the briefs' predictive lines.

**horizon-scanning** is strategic forecasting: identifying weak signals of emerging threats before they materialize, with trend analysis and scenario development. Input is a body of reporting, output is a set of emerging-threat signals and scenarios. It fits the weekly roundup occasionally; it is too heavy and too strategic for the daily brief.

## Source and evidence rigor

**quality-of-information-check** is the CIA Tradecraft Primer's Quality of Information Check adapted for vendor and press CTI. It resolves each document to its originating source, splits it into claims, and grades every claim on two written elements (access level, meaning how the source knows, and claim support, meaning what backs the statement) against a fixed rubric with hard caps, where five outlets citing one vendor report count as one source. Input is a URL, pasted report, or event; output is a graded claim table, a gaps list, a deception screen, and JSON. It is the default first step for ACH, threat-assessment, and writing-assessments. It needs no external key but it is thorough and slow, which makes it better suited to interactive report-grading than to the 07:00 brief.

**claim-extraction** turns one document into five to twelve atomic claims, each typed (observation, attribution, assessment, actor claim, victim disclosure) and anchored to the verbatim sentence it rests on, preserving the source's own hedging. It does not grade; it prepares the claim list that quality-of-information-check, ACH, key-assumptions-check, intelligence-writing, writing-assessments, and threat-actor-profiling consume. Input is a report, output is the typed claim list. A building block for the rigor pipeline, mostly invoked by other skills.

**source-provenance** follows an article's links and named attributions back to the originating vendor, government, victim, or actor document and returns the full chain, the primary's stated access and confidence language, publication dates, and every hop it could not resolve. It is deterministic (a script or the Liberty91 platform resolves the chain, the model does not reconstruct it from memory) and it works on any URL with no API key. Input is a URL, output is the provenance chain. High value and zero cost for keeping the briefs honest about where a claim actually came from, best run interactively or as a provenance check on brief sources.

**source-assessment** rates a source on the NATO Admiralty Scale (reliability A to F, credibility 1 to 6). Input is a source and its reporting, output is the two-axis rating. No key. This is already wired into your daily brief, which is correct: it is the one rigor skill that belongs on every item the bot ships, because it tells the reader how much to trust each line.

**quality-control** is a peer-review checklist and quality standard for finished products, and it also validates the evidence schema and grading caps produced by quality-of-information-check and claim-extraction, rejecting outputs that break the schema or the caps. It is loaded by a quality-reviewer role. Meta and interactive; it gates products rather than generating content.

## Writing and products

**intelligence-writing** holds the conventions for finished intelligence products: BLUF first, active voice, clear sourcing, and the templates for flash reports, threat assessments, briefings, and FINTEL. Input is your findings, output is a product that follows house conventions. It directly improves how the briefs read, and it pairs with your own CLAUDE.md style rules.

**writing-assessments** provides the distinct templates and section ordering for threat, risk, and vulnerability assessments, and prefers graded evidence from quality-of-information-check (running it first on raw input, capping at Moderate when evidence is ungraded). Input is a topic plus evidence, output is a structured assessment. Interactive product work rather than a per-brief step.

**threat-assessment** is the formal methodology Intent plus Capability plus Opportunity equals Threat Level, again preferring graded evidence and capping confidence at the weakest load-bearing claim. Input is an actor or scenario plus evidence, output is a rated threat assessment. A deliberate, interactive product.

**vulnerability-intelligence** prioritizes CVEs by combining weaponization status, EPSS score, and CISA KEV listing into a patch-now-versus-later recommendation. Input is a CVE or set of CVEs, output is a ranked recommendation with the exploitation context. It pairs tightly with your collector (which already pulls KEV) and the bot's `cve-status` tool, needs no extra key, and sharpens the daily brief's vulnerability section more than almost anything else available.

**control-coverage-mapping** joins a control baseline to ATT&CK using a versioned evidence base of 9,545 control-to-technique mappings from six sources, producing four ranked lists (addressed strongly, addressed weakly, real gaps, and techniques no control anywhere addresses). Input is a control set plus a technique list (from threat-actor-profiling or lookup-liberty91), output is the coverage analysis. Valuable for control-gap and board work, which is not what this bot does, so it is occasional at best here.

## Threat knowledge cells (self-updating)

These are living reference cells. Each one carries current knowledge on its domain and updates itself as you use it. They take a question and return structured domain context (actors, families, markets, TTPs). They need no API key. Their value to the bot is as context the brief can lean on when a topic comes up.

**ransomware-ecosystem** covers RaaS dynamics, affiliate markets, inter-group attribution, leak-site behavior, and recent group activity (LockBit lineage, ALPHV/BlackCat, RansomHub, Akira, Play, Qilin, Cl0p, Medusa). It is already wired into the weekly roundup and the fin-ransomware-flash job, and correctly so: the flash job is entirely about ransomware groups and victims, and this cell is what turns a bare victim name into a one-line group profile with TTPs.

**infostealers** covers stealer families (LummaC2, RedLine, Vidar, Stealc, Raccoon, Rhadamanthys) and log marketplaces (Russian Market, BidenCash, the Hudson Rock corpus). It is directly relevant because stealers dominate what your dark-web triage pipeline sees, stealer logs drive credential exposure, and that exposure ties straight into financial fraud, which the flash job cares about.

**initial-access-brokers** covers the IAB market, broker handles, access pricing, and the broker-to-ransomware pipeline. It gives the ransomware briefs their upstream context: how the victim was likely accessed before the ransomware group arrived.

**carding-financial-fraud** covers carding, BIN attacks, payment-card breach markets, the fullz and CVV trade, and the major autoshops (BidenCash, Brian's Club, Russianmarket, B1ack's Stash). It is the most on-point knowledge cell for the financial angle of the fin-ransomware-flash job and any financial-sector brief.

**phishing-social-engineering** covers phishing campaigns, BEC, pretexting, AiTM kits, and phishing-kit families. A common brief topic and a frequent initial-access vector worth the context.

**supply-chain-threats** covers vendor and software supply-chain compromise (SolarWinds, Kaseya, 3CX, MOVEit, XZ-utils style) and dependency-injection risk. Useful when a supply-chain event hits the news cycle the brief covers.

**hacktivism** covers DDoS-claiming and politically motivated groups (Killnet, NoName057(16), IT Army of Ukraine, Anonymous Sudan, RipperSec). Relevant but lower priority given your financial-sector focus.

**china-cyber-espionage** covers PRC-aligned actors (APT41, Volt Typhoon, Mustang Panda, APT10, APT31, Salt Typhoon) and MSS/PLA campaigns. Context for the weekly roundup when a PRC actor is in play.

**russia-cyber-espionage** covers Russian state actors (APT28, Sandworm, APT29, Turla) and pro-RU fronts, including wartime ICS/OT campaigns. Weekly-roundup context.

**iran-cyber-espionage** covers IRGC and MOIS actors (APT35, APT34, MuddyWater, Imperial Kitten), wiper campaigns, and front personas. Weekly-roundup context.

**dprk-cyber-espionage** covers North Korean actors (Lazarus, APT38, BlueNoroff, Andariel, Kimsuky), revenue-generation and IT-worker schemes, and crypto and supply-chain targeting. The DPRK financial angle (crypto theft, revenue ops) gives it a slight edge over the other regional cells for your financial focus.

**threat-actor-profiling** builds or updates a canonical actor profile (attribution, TTPs, campaigns, infrastructure patterns, intelligence gaps) and supplies the profile template other skills consume. Input is an actor name plus reporting, output is the structured profile. It feeds control-coverage-mapping and anchors the actor sections of the weekly roundup.

**campaign-tracking** documents a named campaign across time and victims, providing the template (timeline, attribution, victimology, attack chain, Diamond Model mapping, IOC clusters) and the active-to-historical lifecycle. Input is a multi-incident cluster, output is a tracked campaign record. Useful for the weekly roundup when a cluster warrants formal tracking.

## Detection engineering

These three turn findings into detections. For your setup they help less than they look, because your YARA drafting already happens in the separate static triage pipeline on the Whonix box, and the bot is a reporting agent, not a detection deployer.

**sigma-writing** produces vendor-agnostic SIGMA detection rules from a behavior or finding, with the format spec and a writing guide. Input is a behavior (often from hash-investigation or malware-analysis), output is a SIGMA rule. It could add a detection snippet to a brief, but it is not wired in and is better used interactively.

**yara-writing** produces static-content YARA rules for a sample or family. Input is a sample or pattern set, output is a YARA rule. Your triage pipeline already drafts YARA per novel sample, so this duplicates existing capability and belongs to that workflow rather than the bot.

**kql-writing** produces KQL for Microsoft Sentinel, Defender, or Azure Log Analytics. Input is a finding, output is a KQL query. You run no Sentinel or Defender behind this bot, so it has no target.

**mitre-attack** queries techniques, groups, software, and mitigations from the local `enterprise-attack.json` dataset. Input is a technique ID or name (or a group or software), output is the matching ATT&CK entity. It needs no network and no key because the dataset is local. It is already wired into the daily and weekly jobs, correctly, because it supplies the ATT&CK IDs for every brief and the TTP line in the fin-ransomware-flash note.

## Collection, sharing, and standards

**darkweb-collection** is a full dark-web collection methodology: a vendor-first access posture, sourced reference lists for 35-plus forums and 30-plus Telegram channels, an OPSEC primer, a passive-monitoring strategy, and bundled Python CLIs for onion-index search, Telegram monitoring, and local keyword matching. Input is a collection goal, output is a selector list or monitoring setup. You already run a separate dark-web triage pipeline and a collector that pulls Telegram and deepdarkCTI, so most of this is redundant with infrastructure you have.

**osint-methodology** is a structured OSINT collection methodology (planning, collection techniques, search operators, documentation), loaded by an osint-researcher role. Input is a collection question, output is a collection plan and documented findings. Your collector already handles routine collection, so this is interactive and occasional.

**intelligence-sharing** covers external dissemination: ISAC participation, TAXII feeds, MISP communities, FIRST, STIX-based sharing, and TLP-governed distribution. Input is a product to share, output is the sharing model and mechanism. Your bot already delivers to Telegram and the collector feeds MISP, so this is mostly program-level guidance.

**stix-bundle** is the STIX 2.1 creation reference: object types, relationships, JSON templates, and the per-claim mapping of evidence grades to STIX confidence (and the reverse on import). Input is a set of entities and relationships, output is a STIX 2.1 bundle. Useful when publishing structured intel to MISP or OpenCTI, which you can do, but occasional.

## Program management

**pir-management** manages Priority Intelligence Requirements end to end: create, review, retire, refine, and align collection and analysis to the current PIR set. Input is your intelligence priorities, output is a managed PIR set. Your briefs already read `pirs.md` to decide what to prioritize, so keeping that set sharp matters, but this is setup-time and periodic, not per-run.

**stakeholder-management** maps and re-maps stakeholder needs so products reach the right people in the right format. Input is your audience, output is a stakeholder-to-format map. Setup-time work that shapes the briefs once, not every run.

**maturity-assessment** benchmarks a CTI program against a five-level model across six dimensions and recommends what to improve next. Input is your program's current state, output is a maturity score and a prioritized improvement list. A one-off or periodic exercise.

**feedback-loops** implements continuous-improvement loops: consumer feedback, analyst retrospectives, and source-quality tracking. Input is feedback and outcomes, output is tracked quality signals and process adjustments. A program-level practice, not a per-brief step.

**sops** is the standard-operating-procedures reference (daily triage, IOC processing, flash-report cadence, actor-profile updates, briefing schedule). Input is a process question, output is the relevant SOP. Operational documentation that shapes how you run the bot rather than what it produces.

---

# Part 2: Ranking 1 to 78 for the Hermes Telegram Bot

Rank 1 is most valuable to this specific bot. The ordering weights three things: whether the skill improves the daily brief, weekly roundup, or fin-ransomware-flash job; whether its API key is actually live; and whether it adds analytic rigor the briefs should carry. It penalizes keyless lookups, duplicates of what the collector already does, skills aimed at platforms you do not run, and skills that belong to the separate static triage pipeline.

1. **ransomware-ecosystem** — Already wired into the weekly roundup and the fin-flash job; the flash job is entirely ransomware, and this cell turns a bare victim name into a group profile with TTPs. No key needed.
2. **mitre-attack** — Already wired into both briefs; local dataset, no key, supplies the ATT&CK IDs on every brief item and the TTP line in the flash note.
3. **source-assessment** — Already wired into the daily brief; the one rigor skill that belongs on every shipped line, telling the reader how far to trust it. No key.
4. **vulnerability-intelligence** — Sharpens the daily brief's CVE section directly, pairs with the collector's KEV feed and the `cve-status` tool, turns raw CVEs into patch-now-versus-later calls. No extra key.
5. **ioc-enrichment-workflow** — The single biggest available upgrade to the daily brief: orchestrates your live lookups into one enriched record per IOC instead of bare indicators. Depends only on keys you already have.
6. **confidence-levels** — Cheap, keyless rigor that caps every published judgment to its weakest claim. Every brief judgment should carry it.
7. **likelihood-language** — Cheap, keyless, calibrates the briefs' forward-looking lines so the probability words mean something consistent.
8. **tlp-guide** — The briefs leave the lab, so TLP marking is a release gate, and the README already limits visibility to CLEAR/GREEN/AMBER. No key.
9. **intelligence-writing** — BLUF, active voice, and clear sourcing conventions that make the finished briefs read like real products and pair with your style rules.
10. **lookup-virustotal** — Live key and the broadest single enrichment source, covering IPs, domains, hashes, and URLs; the backbone of every investigation chain.
11. **lookup-otx** — Live key; the community-pulse layer that tells the brief whether an indicator is already part of a reported campaign.
12. **infostealers** — Stealers dominate your dark-web feed and drive the credential exposure that feeds financial fraud, which the flash job cares about. No key.
13. **carding-financial-fraud** — The most on-point knowledge cell for the financial angle of the fin-flash job and any financial-sector brief. No key.
14. **lookup-abuseipdb** — Live key; the fastest way to separate an abusive IP from a clean one in a brief.
15. **lookup-greynoise** — Live key; keeps the brief from elevating mass-scanner IPs as targeted threats (negative filtering is the value).
16. **lookup-urlscan** — Live key; the detonation-lite step for suspicious links, and its whole chain (url-investigation) works end to end on your box.
17. **lookup-misp** — Live, two-way; your collector and `misp-recent` already center on MISP, so this dedups indicators on the way in and publishes findings back.
18. **initial-access-brokers** — Gives the ransomware briefs their upstream context (how the victim was accessed before the ransomware arrived). No key.
19. **lookup-opencti** — Live, two-way; check the knowledge base for known IOCs and publish findings back. Slightly below MISP because your tooling leans harder on MISP.
20. **threat-actor-profiling** — Anchors the actor sections of the weekly roundup and feeds control-coverage-mapping; keyless canonical profiles.
21. **source-provenance** — Keyless, deterministic, traces a claim back to its primary source and flags rewrites; high value for honest brief sourcing, best run as a source check.
22. **url-investigation** — All three backends (URLScan, VT, OTX) are live, so this chain works fully; strong for link-heavy brief items.
23. **dprk-cyber-espionage** — The DPRK revenue and crypto-theft angle gives it an edge over the other regional cells for your financial focus. No key.
24. **campaign-tracking** — Formalizes multi-incident clusters for the weekly roundup (timeline, victimology, Diamond Model). No key.
25. **ip-investigation** — Chains four live sources (VT, AbuseIPDB, GreyNoise, OTX); the Shodan and Censys legs are dead, so it is strong but not complete.
26. **domain-investigation** — Chains VT, URLScan, and OTX (live); the Shodan and ransomware.live legs are keyless, so partial but useful.
27. **phishing-social-engineering** — Common brief topic and frequent initial-access vector worth the standing context. No key.
28. **quality-of-information-check** — Strong grading rigor, keyless, but thorough and slow, so better for interactive report-grading than the fast 07:00 brief.
29. **indicator-pivoting** — Expands one IOC into a cluster using your live lookups; real value, but more interactive than scheduled.
30. **russia-cyber-espionage** — Weekly-roundup context for a high-activity actor set. No key.
31. **china-cyber-espionage** — Weekly-roundup context (Volt Typhoon, Salt Typhoon, and so on). No key.
32. **iran-cyber-espionage** — Weekly-roundup context, including front personas and wipers. No key.
33. **supply-chain-threats** — Valuable when a supply-chain event is in the brief's news window. No key.
34. **claim-extraction** — The building block that feeds grading, ACH, and profiling; mostly invoked by other skills rather than standing alone.
35. **key-assumptions-check** — Sharpens high-impact weekly assessments by testing load-bearing assumptions; heavier, interactive.
36. **hash-investigation** — VT and OTX legs are live so it works, but hash triage is mostly your separate pipeline's job, so the bot should not lead on it.
37. **intelligence-sharing** — Program-level dissemination guidance; your bot already ships to Telegram and the collector feeds MISP, so limited incremental value.
38. **hacktivism** — Real context but lower priority given your financial-sector focus. No key.
39. **horizon-scanning** — Fits the weekly roundup occasionally for emerging-threat signals; too strategic and heavy for the daily brief.
40. **threat-assessment** — Solid formal methodology, but a deliberate interactive product rather than a per-brief step.
41. **writing-assessments** — Assessment templates for interactive product work, not scheduled briefs.
42. **ach** — Powerful for hard attribution calls, but heavy and interactive, not a brief step.
43. **devils-advocacy** — Useful to stress-test a specific weekly judgment before release; invoked on demand.
44. **structured-analytic-techniques** — The SAT selector; meta value in pointing you at the right technique, no direct output for the jobs.
45. **stix-bundle** — Useful when publishing structured intel to MISP or OpenCTI (both live), but occasional.
46. **ioc-export** — Export formatting for dissemination; occasional, matters only when you are shipping IOCs out.
47. **pir-management** — The briefs read `pirs.md`, so keeping the PIR set sharp matters, but this is periodic setup, not per-run.
48. **control-coverage-mapping** — Strong for control-gap and board work, which is not what this bot does; occasional here.
49. **cti-orchestrator** — Real value for ad-hoc interactive queries to the bot, but the scheduled jobs name their skills explicitly, so it does not touch them.
50. **quality-control** — Gates product quality and validates grading schemas; meta and interactive rather than content-producing.
51. **stakeholder-management** — Shapes the briefs once at setup (audience and format), not every run.
52. **sops** — Operational documentation that shapes how you run the bot, not what it outputs.
53. **osint-methodology** — Your collector already handles routine collection, so this is interactive and occasional.
54. **maturity-assessment** — A periodic program benchmark, no per-job value.
55. **feedback-loops** — A program-improvement practice, not a brief step.
56. **cti-hyperloop** — Doctrine reading; shapes how you think about the program, produces nothing.
57. **sigma-writing** — Could add a detection snippet to a brief, but not wired in and better interactive; detection-deploy is not this bot's role.
58. **cti-setup** — A one-time key-configuration helper; your keys are already set, so its job is done.
59. **darkweb-collection** — Mostly redundant with the separate dark-web pipeline and the collector you already run.
60. **virustotal-api** — Reference doc only; the live lookup-virustotal already wraps it. Marginal.
61. **otx-api** — Reference doc only for the live OTX integration. Marginal.
62. **urlscan-api** — Reference doc only for the live URLScan integration. Marginal.
63. **abuseipdb-api** — Reference doc only for the live AbuseIPDB integration. Marginal.
64. **greynoise-api** — Reference doc only for the live GreyNoise integration. Marginal.
65. **yara-writing** — Duplicates the YARA drafting your triage pipeline already does; belongs to that workflow, not the bot.
66. **malware-analysis** — Belongs to the separate static triage pipeline on the Whonix box, not Hermes.
67. **kql-writing** — No Sentinel or Defender behind this bot, so no target.
68. **lookup-ransomwarelive** — No key, and the collector already ingests ransomware.live into `intel.db`, so the data path is covered without it.
69. **lookup-shodan** — No key; it is the missing leg in the investigation chains, but the skill itself cannot run.
70. **lookup-censys** — No key, and even keyed the free tier is 250 queries a month. Dead weight.
71. **lookup-reversinglabs** — No key and aimed at deep malware enrichment, which is the separate pipeline's job.
72. **lookup-crowdstrike** — No key and needs a paid Falcon Intelligence subscription. Dead weight.
73. **lookup-sentinel** — No key and you run no Sentinel workspace behind the bot. Dead weight.
74. **lookup-liberty91** — No key and you do not run the Liberty91 platform. Dead weight.
75. **shodan-api** — Reference doc for a service with no key. Dead weight.
76. **censys-api** — Reference doc for a service with no key. Dead weight.
77. **crowdstrike-api** — Reference doc for a service with no key and no subscription. Dead weight.
78. **reversinglabs-api** — Reference doc for a service with no key, aimed at the separate triage pipeline. Deadest for this bot.

---

## Bottom line

The skills that earn their place in this bot cluster at the top: the three already wired (ransomware-ecosystem, mitre-attack, source-assessment), the rigor skills that cost nothing and tighten every brief (confidence-levels, likelihood-language, tlp-guide, vulnerability-intelligence), and the enrichment layer your live keys make real (ioc-enrichment-workflow plus the VT/OTX/AbuseIPDB/GreyNoise/URLScan/MISP/OpenCTI lookups). The two highest-value additions not yet wired are ioc-enrichment-workflow (so brief IOCs arrive enriched) and vulnerability-intelligence (so the CVE section becomes a real patch call).

The bottom of the list is genuine dead weight for this bot: seven keyless lookups and four reference docs for services you have no key for, plus the detection-engineering and malware skills that belong to your separate Whonix triage pipeline. None of them hurt anything sitting in the clone, but none of them should be loaded into a scheduled job. If you ever key Shodan, the investigation chains (ranks 25 and 26) jump, because Shodan is their missing leg.
