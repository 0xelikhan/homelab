# cti-skills-local

Local additions to the upstream [Liberty91LTD/cti-skills](https://github.com/Liberty91LTD/cti-skills)
pack, deployed on the Hermes box (LXC 120) at `/home/hermes/cti-skills`. The
upstream clone is reproducible, so only these additions are version-controlled here.

## Contents

- `tools/clis/hudsonrock.js` — Hudson Rock Cavalier infostealer stealer-log lookups (`domain|email|ip`). Free OSINT endpoints, no key; `HUDSONROCK_API_KEY` optional for the paid tier.
- `tools/clis/circl-onion.js` — CIRCL AIL onion-lookup (`onion <addr>`). First/last seen, titles, tags, crypto addresses. No key.
- `skills/lookup-hudsonrock/`, `skills/lookup-circl-onion/` — the matching lookup-skill docs.

## Deploy

Drop these into a `cti-skills` checkout at the same paths:

    cp -r tools/clis/*.js   ~/cti-skills/tools/clis/
    cp -r skills/lookup-*   ~/cti-skills/skills/
