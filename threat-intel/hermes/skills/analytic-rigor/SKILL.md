---
name: analytic-rigor
description: >
  Lightweight analytic tradecraft for every brief. One skill that applies claim
  extraction, source/claim grading, the confidence ceiling, a key-assumptions
  check, Analysis of Competing Hypotheses (ACH) and a devil's-advocate challenge,
  and points to the right assessment structure. Use it to grade what the brief
  reports and to discipline every judgement, without loading six separate SAT
  skills. For a full standalone product (a formal ACH, a threat or risk
  assessment, a deep quality-of-information review), escalate to the dedicated
  skill named at the end.
user-invocable: true
metadata:
  category: tradecraft
  consolidates: [quality-of-information-check, claim-extraction, key-assumptions-check, ach, devils-advocacy, structured-analytic-techniques, threat-assessment, writing-assessments]
  created: "2026-11-12"
---

# Analytic Rigor

The rigor layer the brief runs over its findings. Apply the first three sections to
every item; apply the rest only to the day's high-impact or ambiguous judgements.
This skill is deliberately compact. When a finding needs a full, free-standing
analytic product, use the standalone skill named in **Escalate** below.

## 1. Extract claims before grading

Split each source into 5 to 12 atomic claims. One fact per claim, anchored to the
verbatim sentence it rests on. Type each claim: observation, attribution,
assessment, actor claim, or victim disclosure. Preserve the source's own hedging
("reportedly", "assesses with moderate confidence"). Do not grade yet, and do not
merge two facts into one claim. This is what makes every later judgement checkable.

## 2. Grade the source and the claim

Resolve each document to its **originating source** before grading it. Five outlets
repeating one vendor report are one source, not five. Grade on two elements:

- **Access**: how the source could know (first-hand incident response, telemetry,
  victim statement, second-hand, speculation).
- **Support**: what backs the specific claim (named evidence, a quote, a sample,
  nothing).

Apply hard caps: anything that cannot be traced to a primary source is capped, not
guessed; an actor's self-claim shows only that the claim was made; a self-serving
statement stays Reported until an independent originator supports it. Record an
Admiralty rating (A-F reliability, 1-6 credibility) on every item for the brief;
the two-element grade is the rationale behind it, not the same thing.

## 3. Cap confidence at the weakest load-bearing claim

A judgement is only as strong as the weakest claim it depends on. If a key judgement
rests on a single originator, on the absence of reporting, or on an uncorroborated
claim, cap it there. **When the evidence is ungraded, cap the whole judgement at
Moderate confidence.** Express the result with `/confidence-levels` (low / moderate /
high) and `/likelihood-language` (the fixed ICD 203 probability words); keep facts
and assessments apart, and never swap a probability word for a number.

## 4. Key assumptions check (high-impact judgements)

Before publishing a judgement that drives an action, list what it assumes. For each
assumption state how confident you are it holds and how much the judgement depends
on it. Flag any assumption that is **load-bearing and low-confidence**: that is where
the judgement breaks. Say in one line what would have to be true for the assumption
to fail.

## 5. ACH (ambiguous attribution or competing explanations)

When two or more explanations fit the evidence (contested attribution, unclear root
cause):

1. Generate the hypotheses before weighing evidence, including the ones you doubt.
2. Build a consistency matrix: each claim against each hypothesis (consistent,
   inconsistent, not applicable).
3. Drop non-diagnostic rows (claims consistent with every hypothesis prove nothing).
4. The hypothesis with the **least inconsistent** evidence leads, not the one with
   the most consistent. Name the few claims that actually discriminate.
5. State what new evidence would change the answer.

## 6. Devil's advocate (before releasing a high-impact judgement)

Take the brief's own lead judgement and build the strongest case that it is wrong:
the contrary evidence, the weak assumption, the alternative read. This is a
contrarian stress test, not a forecast of the adversary's next move. If the judgement
survives, say so; if it cracks, soften the confidence or add the caveat.

## 7. Pick the assessment structure

- **Threat assessment**: Intent + Capability + Opportunity = Threat Level. Use for
  "how dangerous is this actor to us".
- **Risk assessment**: likelihood times impact against a specific asset or decision.
- **Vulnerability assessment**: exposure, exploitability, and what it would take to
  fix. Use for a CVE or a control gap.

Lead every assessment with the bottom line and its confidence, then the reasoning.

## Escalate to the standalone skill

This skill is the fast path for the briefs. For a full, free-standing product, the
originals remain available on demand:

- `/quality-of-information-check`: the full CIA-primer grading run with deception
  screen and JSON output.
- `/ach`: the full weighted consistency matrix with sensitivity analysis.
- `/threat-assessment` and `/writing-assessments`: the complete assessment templates.
- `/key-assumptions-check`, `/devils-advocacy`, `/claim-extraction`: the full
  standalone procedures.
- `/structured-analytic-techniques`: the selector, when you are not sure which
  technique a hard problem needs.
