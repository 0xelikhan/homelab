---
name: lookup-hudsonrock
description: Use to check whether a domain, email, or IP appears in Hudson Rock's infostealer (stealer-log) dataset. Returns compromised-machine counts, infection dates, OS, and the masked top logins/passwords per infected host. Retrieval only - does not interpret. Strongest signal for credential-exposure and financial-sector targeting PIRs.
metadata:
  version: 1.0.0
  tags: [lookup, threat-intel, infostealer, credential-exposure]
  api: hudsonrock
  default_source_reliability: B
  default_information_credibility: 2
---

# lookup-hudsonrock

Queries Hudson Rock's Cavalier OSINT API for infostealer stealer-log exposure. Retrieval only - do not interpret.

## When to invoke

- Checking whether an organisation's domain, an email, or an IP shows up in infostealer logs
- Credential-exposure or financial-sector exposure assessment (a pivot on a strong hit, not every IOC)
- Corroborating an initial-access or account-takeover lead with stealer-log evidence

## How to invoke

```bash
node tools/clis/hudsonrock.js domain <domain>
node tools/clis/hudsonrock.js email <email>
node tools/clis/hudsonrock.js ip <ip>
```

Free OSINT endpoints, no key. `HUDSONROCK_API_KEY` is appended for the paid tier if set; its absence is normal. `--dry-run` previews the request.

## Response format

`domain` returns aggregate exposure (the free tier does not return per-record stealers for a domain):

```yaml
source: hudsonrock
indicator: <domain>
type: domain
found: true|false
compromised_machines: <count of machines holding a credential for this domain>
employees_compromised: <count>
users_compromised: <count>
third_parties_compromised: <count>
top_employee_urls: [{url, occurrence}]    # login portals most seen in logs
top_client_urls: [{url, occurrence}]
```

`email` and `ip` return per-infection records (credentials masked by Hudson Rock):

```yaml
found: true|false
stealer_count: <n>
message: <Hudson Rock exposure notice>
total_corporate_services: <n>
total_user_services: <n>
stealers:
  - date_compromised: <ISO date>
    computer_name: <host>
    operating_system: <OS>
    malware_path: <path or Not Found>
    antiviruses: [<av>]
    ip: <ip or Not Found>
    top_logins: [<masked>]
    top_passwords: [<masked>]
```

`found: false` means the indicator is not in the stealer-log dataset.

## Rate limits

Free OSINT tier, generous for interactive use. The paid Cavalier API raises limits and unmasks records.

## Source reliability (Admiralty default)

**B2** (usually reliable, probably true). Hudson Rock parses real stealer logs; the exposure signal is strong, but the free tier masks specifics and timestamps reflect log aggregation, not live compromise.

## Related skills

- `/lookup-circl-onion` - dark-web onion metadata pivot
- `/infostealers`, `/carding-financial-fraud`, `/initial-access-brokers` - assessment context
- `/indicator-pivoting`, `/ioc-enrichment-workflow`

## See also

- CLI source: `tools/clis/hudsonrock.js`
- Free tools: https://www.hudsonrock.com/free-tools
