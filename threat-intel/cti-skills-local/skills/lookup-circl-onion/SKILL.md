---
name: lookup-circl-onion
description: Use to check a .onion address against CIRCL's AIL onion-lookup dataset. Returns first/last seen, page titles, languages, AIL tags, and any extracted cryptocurrency addresses. Retrieval only - does not interpret, and never visits the onion. Useful for dating a dark-web service and pivoting without touching Tor.
metadata:
  version: 1.0.0
  tags: [lookup, threat-intel, darkweb, onion]
  api: circl-onion
  default_source_reliability: B
  default_information_credibility: 2
---

# lookup-circl-onion

Queries CIRCL's AIL onion-lookup for metadata on a Tor hidden service. Retrieval only - do not interpret, and never visit the onion itself.

## When to invoke

- Dating a .onion service (first/last seen) named in a leak post or report
- Pivoting from an onion to crypto addresses or page titles without connecting to Tor
- Corroborating that a dark-web service is known and active

## How to invoke

```bash
node tools/clis/circl-onion.js onion <address>
```

No key. Accepts a bare `.onion` host or a full onion URL (protocol and path are stripped). `--dry-run` previews the request.

## Response format

```yaml
source: circl-onion
indicator: <onion address>
type: onion
seen: true|false
first_seen: <date>
last_seen: <date>
languages: [<lang>]
titles: [<page title>]        # capped at 10
tags: [<AIL infoleak tags>]
crypto_addresses: {<field>: [<addr>]}   # only when AIL extracted any
```

`seen: false` (empty upstream record) means the onion is not in CIRCL's dataset.

## Rate limits

Free, generous. One request per invocation; pace a loop lightly.

## Source reliability (Admiralty default)

**B2** (usually reliable, probably true). CIRCL/AIL is a trusted crawler; coverage is partial and metadata reflects when AIL last crawled the service.

## Related skills

- `/lookup-hudsonrock` - infostealer exposure pivot
- `/darkweb-collection` - observe-only handling of dark-web sources
- `/indicator-pivoting`, `/ioc-enrichment-workflow`

## See also

- CLI source: `tools/clis/circl-onion.js`
- Service: https://onion.ail-project.org
