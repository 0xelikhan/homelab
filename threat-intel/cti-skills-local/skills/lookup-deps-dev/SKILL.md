---
name: lookup-deps-dev
description: Use to pivot on an open-source package during a software-supply-chain investigation. Given a package (npm, PyPI, Go, Maven, Cargo, NuGet, RubyGems), returns its version history and publish dates, known advisories mapped to CVEs and CVSS, declared license, source repo with OpenSSF Scorecard, and its own dependency graph. Also reverses a file hash to known package versions. Retrieval only - does not interpret.
metadata:
  version: 1.0.0
  tags: [lookup, supply-chain, package, osv, scorecard]
  api: deps.dev
  default_source_reliability: A
  default_information_credibility: 1
---

# lookup-deps-dev

Queries deps.dev (Google Open Source Insights) for open-source package metadata. Retrieval only - do not interpret.

## When to invoke

- A supply-chain lead names a specific package (e.g. from the OpenSourceMalware feed or a GHSA/exploit item): check its version history, publish dates, advisories, license, repo health, and dependencies.
- Triaging a suspected malicious or typosquatted package: a brand-new package, a one-version package, or a low OpenSSF Scorecard are supporting signals.
- Mapping an advisory (OSV or GHSA id) to its CVE aliases and CVSS.
- Reversing a file hash (MD5/SHA-1/SHA-256/SHA-512) from a sample to a known package version.

Not an IOC enrichment for IPs, domains, or URLs; those go through the standard VT/AbuseIPDB/OTX/URLScan path. This is package-scoped only.

## How to invoke

```bash
node tools/clis/deps-dev.js pkg <system> <name> [version]   # system: npm|pypi|go|maven|cargo|nuget|rubygems
node tools/clis/deps-dev.js advisory <OSV-or-GHSA-id>
node tools/clis/deps-dev.js hash <md5|sha1|sha256|sha512>    # hex or base64
```

Free, no key. `--dry-run` previews the request. Scoped npm names (`@scope/name`) and Maven coordinates (`group:artifact`) are URL-encoded automatically.

## Response format

`pkg` (version omitted resolves to the default/latest):

```yaml
source: deps.dev
type: package
system: npm
name: <package>
found: true|false
version_count: <n>
default_version: <ver>
queried_version: <ver>
published: <ISO date>          # when this version shipped
is_default: true|false
deprecated: true|false
licenses: [<SPDX>]
advisory_count: <n>
advisories:
  - id: <OSV/GHSA>
    cves: [CVE-...]
    cvss3: <0-10>
    url: <advisory url>
source_repo: github.com/<org>/<repo>
project:
  stars: <n>
  forks: <n>
  scorecard_overall: <0-10>    # OpenSSF Scorecard; low is a weak-supply-chain signal
  weak_checks: [<check>:<score>]  # checks scoring <= 3
dependencies: { total, direct, indirect }   # npm/cargo/maven/pypi only; this package's own supply chain
```

`advisory`:

```yaml
type: advisory
id: GHSA-...
aliases: [CVE-..., ...]
cves: [CVE-...]
cvss3_score: <0-10>
cvss3_vector: <vector>
url: <url>
```

`hash` maps an artifact hash to the package version(s) it belongs to:

```yaml
type: hash
hash_type: SHA256
found: true|false
match_count: <n>
matches:
  - { system, name, version }
```

`found: false` means deps.dev has no record. deps.dev has no reverse-dependents endpoint, so this shows a package's own dependencies, not who depends on it.

## Rate limits

Public Google service, generous for interactive use. `pkg` fans out a few calls (version, advisories, project, dependencies); a run is a handful of requests. 429 is surfaced as an error.

## Source reliability (Admiralty default)

**A1** (completely reliable, confirmed) for the factual metadata: versions, publish dates, licenses, and repo links come straight from the official registries, and advisory data is OSV-backed. Treat the OpenSSF Scorecard as a heuristic signal, not a verdict.

## Related skills

- `/lookup-hudsonrock` - infostealer credential-exposure pivot
- `/malware-analysis`, `/indicator-pivoting`, `/ioc-enrichment-workflow`

## See also

- CLI source: `tools/clis/deps-dev.js`
- API docs: https://docs.deps.dev/api/v3/
