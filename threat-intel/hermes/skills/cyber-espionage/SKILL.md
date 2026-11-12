---
name: cyber-espionage
description: >
  Consolidated threat-context pack. Use for state-sponsored cyber espionage and
  for the recurring non-ransomware threat types a brief needs as context: China
  (APT41, Volt/Salt/Silk Typhoon, Mustang Panda, UNC5221), Russia (APT28/29,
  Sandworm, Turla, Gamaredon, GRU hacktivist fronts), Iran (APT35/42, MuddyWater,
  OilRig, Void Manticore/Handala, CyberAv3ngers, Predatory Sparrow), DPRK (Lazarus,
  BlueNoroff, Kimsuky, TraderTraitor, Contagious Interview, IT-worker scheme),
  phishing and social engineering (BEC, AiTM, ClickFix, quishing, PhaaS),
  supply-chain and third-party compromise, hacktivism and DDoS fronts, and
  horizon-scanning for emerging threats. Loads only the one cell the day's activity
  needs, so it carries all eight knowledge bases at a fraction of the context cost.
user-invocable: true
metadata:
  category: knowledge-cell
  consolidates: [china-cyber-espionage, russia-cyber-espionage, iran-cyber-espionage, dprk-cyber-espionage, phishing-social-engineering, supply-chain-threats, hacktivism, horizon-scanning]
  created: "2026-11-12"
  confidence: moderate
---

# Cyber Espionage & Threat Context

One skill that holds eight knowledge cells. Each cell is a full, cited, self-updating
knowledge base kept verbatim in `references/`. **Do not read every cell.** Identify
which one (rarely two) the current activity touches, load only that file, and work
from it. This is the whole point of the pack: the brief gets the same depth as eight
separate skills while loading one short router plus one cell per run.

## How to use

1. Read the routing table below and pick the cell that matches the finding (the
   named actor, the threat type, or the question).
2. Load that one reference file, for example `references/dprk.md`.
3. If a finding genuinely spans two cells (a DPRK supply-chain package compromise,
   a Russian hacktivist OT attack), load both, but no more.
4. If nothing matches, this skill does not apply. Do not load a cell on spec.

## Routing table

| Load this cell | When the activity is | Anchor actors / scope |
|---|---|---|
| `references/china.md` | PRC state-nexus espionage, edge-device and telecom intrusions, critical-infrastructure pre-positioning, IT supply-chain espionage | APT41, Volt Typhoon, Salt Typhoon, Silk Typhoon, Mustang Panda/TA416, APT31, UNC5221/BRICKSTORM, Flax/Linen Typhoon |
| `references/russia.md` | Russian state ops, Ukraine-war wipers/OT, cloud-identity and webmail espionage, GRU-linked hacktivist fronts | APT28, APT29/Midnight Blizzard, Sandworm/APT44, Turla, Static Tundra, Gamaredon, Star Blizzard, Void Blizzard, CARR/NoName057(16) |
| `references/iran.md` | Iranian IRGC/MOIS ops, OT/PLC attacks, destructive/hack-and-leak, fake-recruiter and research-targeting | APT35/42, MuddyWater, APT34/OilRig, Void Manticore/Handala, Nimbus Manticore/UNC1549, CyberAv3ngers; Predatory Sparrow (anti-Iran) |
| `references/dprk.md` | North Korean revenue and espionage, crypto theft, open-source/npm compromise, IT-worker fraud. **Highest-value cell for a financial-sector brief.** | Lazarus, APT38/BlueNoroff, Kimsuky, Andariel, TraderTraitor, Citrine Sleet, Contagious Interview/WaterPlum, Jasper Sleet IT workers |
| `references/phishing.md` | Phishing, BEC, pretexting, AiTM kits, device-code phishing, ClickFix/fake-CAPTCHA, help-desk/voice SE, QR "quishing", PhaaS families | Phishing-kit and PhaaS ecosystem, AiTM operators |
| `references/supply-chain.md` | Third-party/vendor compromise, package and dependency attacks, CI/CD and update-infrastructure hijacking, OAuth token abuse, MSP/RMM abuse | SolarWinds/3CX/MOVEit/XZ-style events, npm/PyPI worms, Cl0p mass-exploitation pattern |
| `references/hacktivism.md` | Politically motivated ops, DDoS-claiming groups, wartime chatter, pro-state OT tampering fronts | NoName057(16), Killnet, Anonymous Sudan, RipperSec, IT Army of Ukraine, CARR/Z-Pentest |
| `references/horizon.md` | Strategic forecasting and weak-signal scanning: "what is coming next", emerging-threat scenarios. Weekly roundup, not the daily brief | Method, not an actor cell: signals, scenarios, early-warning indicators |

## Shared tradecraft (applies to every cell)

- These cells are **information, cited and graded**, not ground truth. Carry the
  cell's own confidence caveats and intelligence gaps into the brief. An actor tag
  on an article is a lead, not attribution.
- Keep attribution evidence-based and caveated. Where a cell records a naming or
  attribution conflict (for example APT27 / Silk Typhoon / UNC5221, or the Poland
  attack's GRU-vs-FSB dispute), reproduce the conflict; do not resolve it silently.
- For a full structured actor profile, route the chosen cell's actor through
  `/threat-actor-profiling`. Map behaviours to ATT&CK with `/mitre-attack` under
  `attack-mapping-rules.md`. Grade and express judgements with `/analytic-rigor`.
- **Live enrichment.** When CrowdStrike Falcon Intelligence credentials are set
  (`$CROWDSTRIKE_CLIENT_ID`), the regional cells can be refreshed with
  `/lookup-crowdstrike actor "<name>"`, `ttps "<name>"` and `reports --actor
  "<name>" --latest` (Panda = PRC, Bear = Russia, Chollima = DPRK, Kitten = Iran).
  No key is configured here today, so treat these as optional and work from the
  cell text.

## Keeping the cells current

Each cell carries a `## Change Log` and `## Sources & References`. To refresh one,
add new reporting with its primary source, update the actor and tooling tables,
move superseded campaigns to Historical rather than deleting them, and append a
change-log row with the date and sources. Keep quotes to one sentence and keep
every new claim tied to a cited source. The cells were last refreshed 2026-09-29;
state their age when a cell drives a judgement.

## Financial-sector priority

For this deployment the daily brief leads with financial-sector threats. In
practice that means `references/dprk.md` (crypto theft, exchange and DeFi
intrusions, the laundering cycle) carries most often, followed by
`references/phishing.md` (BEC and AiTM against finance) and
`references/supply-chain.md` (upstream access to financial software). The regional
espionage cells (china, russia, iran) and `references/hacktivism.md` are context
for the weekly roundup and for specific attribution questions, not every daily run.
