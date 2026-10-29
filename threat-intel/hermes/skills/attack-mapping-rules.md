# ATT&CK mapping rules

Used by `cti-daily-brief` and `cti-weekly-roundup` whenever a technique ID goes into a brief.

## Version

- Map against the ATT&CK data in OpenCTI (the `mitre` connector keeps it current; v20 as of 2026-10).
  Check every ID with `/lookup-opencti` (attack pattern by `x_mitre_id`). If it is missing, it was revoked
  or deprecated: use the replacement and note `T#### revoked, now T####`.
- v19 and v20 changed defense evasion: T1562 Impair Defenses is gone (T1685 Disable or Modify Tools,
  T1686, under the Defense Impairment tactic). Never use an ID from memory.

## Eligibility first

Map a behaviour only if the source text describes it: an action, what it acted on, and enough detail to
match the technique definition. Not eligible on their own:

- a tool or file being present, with no statement that it ran or what it did
- the actor's reputation, other reporting, or what the actor "typically" does
- your own inference that something probably happened
- behaviour named only in mitigations, recommendations or hunting advice
- behaviour from an older campaign or a background section
- IDs from the vendor's own ATT&CK table. Treat that table as a claim to check against the prose.

The source author's own judgement ("we assess credentials were dumped") is eligible as source-assessed.

## Occurrence (how the source knows)

| Status | When |
|---|---|
| observed | the author saw it: telemetry, forensics, logs, analysis of a sample from the incident |
| reported | the author relays a victim's, partner's or other vendor's observation |
| assessed | the author judges it happened without direct observation |
| capability | the source describes what code or a tool can do, not that it ran against a victim |

Never describe capability-only behaviour as something that happened.

## Confidence (how well the text fits the technique)

| Rating | All of these hold |
|---|---|
| High | action and object stated explicitly; the definition's conditions are met; no other technique stays defensible; a sub-technique is used only when the text names the variant |
| Moderate | behaviour described, but one other technique stays defensible or a condition is likely but unstated |
| Low | behaviour thinly described; several techniques fit, or only part of the definition matches |

Any doubt on a High check makes it Moderate. Confidence is about the fit, not whether it happened.

## Discipline

- Each mapping carries a short verbatim quote from the retrieved text and its OpenCTI report link. If you
  cannot quote it, do not map it. Feed summaries are often truncated: map only what the retrieved text says.
- Prefer the parent technique when the text does not describe the sub-technique.
- Where two techniques are defensible, map the stronger one and name the other as an alternative.
- Do not add techniques to make a tactic or the coverage table look complete.
- In the brief, write each technique as `T#### Name (occurrence, confidence)`.
