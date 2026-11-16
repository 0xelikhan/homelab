#!/usr/bin/env node
// tools/clis/deps-dev.js - deps.dev (Google Open Source Insights) supply-chain pivot.
// Zero deps, Node >= 18. Free, no key (Google API Terms of Service).
//
// Usage:
//   node deps-dev.js pkg <system> <name> [version]   versions, advisories+CVE, license, source repo, OSSF scorecard, deps
//   node deps-dev.js advisory <OSV|GHSA id>          advisory -> CVE aliases, CVSS, url
//   node deps-dev.js hash <md5|sha1|sha256|sha512>   reverse a file hash (hex or base64) to known package versions
//
// system: npm | pypi | go | maven | cargo | nuget | rubygems
// --dry-run previews the request URL without calling out.
// Retrieval only; it does not interpret. deps.dev has no "dependents" endpoint,
// so this shows a package's own supply chain, not who depends on it.

const https = require('https');
const API = 'https://api.deps.dev/v3';
const SYSTEMS = ['npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'rubygems'];
const DEP_SYSTEMS = ['npm', 'cargo', 'maven', 'pypi']; // GetDependencies is limited to these

let DRY = false;

function die(msg, code = 1) { process.stderr.write(`error: ${msg}\n`); process.exit(code); }

function usage() {
  process.stderr.write(
    'usage:\n' +
    '  deps-dev.js pkg <system> <name> [version]   # system: ' + SYSTEMS.join('|') + '\n' +
    '  deps-dev.js advisory <OSV|GHSA id>\n' +
    '  deps-dev.js hash <md5|sha1|sha256|sha512>    # hex or base64\n\n' +
    'Free, no key. --dry-run previews the request.\n');
  process.exit(3);
}

const enc = (s) => encodeURIComponent(s);

function get(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { Accept: 'application/json', 'User-Agent': 'homelab-cti/1.0' } }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        if (res.statusCode === 404) return resolve({ __notfound: true });
        if (res.statusCode === 429) return reject(new Error('rate limited (429)'));
        if (res.statusCode >= 400) return reject(new Error(`HTTP ${res.statusCode}: ${body.slice(0, 300)}`));
        try { resolve(JSON.parse(body)); } catch { reject(new Error(`invalid JSON: ${body.slice(0, 300)}`)); }
      });
    }).on('error', reject);
  });
}

async function resolveAdvisories(keys) {
  const out = [];
  for (const k of (keys || []).slice(0, 10)) {
    try {
      const a = await get(`${API}/advisories/${enc(k.id)}`);
      if (a && !a.__notfound) {
        out.push({ id: a.advisoryKey?.id || k.id, cves: (a.aliases || []).filter((x) => /^CVE-/i.test(x)),
                   cvss3: a.cvss3Score, url: a.url, title: a.title });
      } else { out.push({ id: k.id }); }
    } catch { out.push({ id: k.id }); }
  }
  return out;
}

async function project(id) {
  const p = await get(`${API}/projects/${enc(id)}`);
  if (!p || p.__notfound) return null;
  return {
    id, stars: p.starsCount, forks: p.forksCount, open_issues: p.openIssuesCount,
    license: p.license,
    scorecard_overall: p.scorecard?.overallScore, scorecard_date: p.scorecard?.date,
    weak_checks: (p.scorecard?.checks || [])
      .filter((c) => typeof c.score === 'number' && c.score <= 3)
      .map((c) => `${c.name}:${c.score}`).slice(0, 10),
  };
}

async function depsSummary(system, name, version) {
  try {
    const d = await get(`${API}/systems/${system}/packages/${enc(name)}/versions/${enc(version)}:dependencies`);
    if (!d || d.__notfound || !Array.isArray(d.nodes)) return null;
    return {
      total: Math.max(0, d.nodes.length - 1), // minus the root (SELF) node
      direct: d.nodes.filter((n) => n.relation === 'DIRECT').length,
      indirect: d.nodes.filter((n) => n.relation === 'INDIRECT').length,
    };
  } catch { return null; }
}

async function pkg(system, name, version) {
  system = system.toLowerCase();
  if (!SYSTEMS.includes(system)) usage();
  if (DRY) { console.log(JSON.stringify({ dry_run: true, url: `${API}/systems/${system}/packages/${enc(name)}` }, null, 2)); return; }
  const info = await get(`${API}/systems/${system}/packages/${enc(name)}`);
  if (!info || info.__notfound) return { source: 'deps.dev', type: 'package', system, name, found: false };
  const versions = info.versions || [];
  const def = versions.find((v) => v.isDefault);
  const vrow = version ? versions.find((v) => v.versionKey?.version === version) : def;
  const target = version || def?.versionKey?.version || versions[versions.length - 1]?.versionKey?.version;
  const base = {
    source: 'deps.dev', type: 'package', system, name, found: true,
    version_count: versions.length, default_version: def?.versionKey?.version, queried_version: target,
    latest_published: versions.map((v) => v.publishedAt).filter(Boolean).sort().slice(-1)[0],
  };
  if (!target) return base;
  const v = await get(`${API}/systems/${system}/packages/${enc(name)}/versions/${enc(target)}`);
  if (!v || v.__notfound) return { ...base, version_found: false };
  const advs = await resolveAdvisories(v.advisoryKeys);
  const repo = (v.relatedProjects || []).find((r) => r.relationType === 'SOURCE_REPO') || (v.relatedProjects || [])[0];
  const proj = repo ? await project(repo.projectKey.id) : null;
  const deps = DEP_SYSTEMS.includes(system) ? await depsSummary(system, name, target) : null;
  return {
    ...base,
    published: v.publishedAt,
    is_default: !!vrow?.isDefault,
    deprecated: !!vrow?.isDeprecated,
    deprecated_reason: vrow?.deprecatedReason || undefined,
    licenses: v.licenses || [],
    advisory_count: advs.length,
    advisories: advs,
    source_repo: repo?.projectKey?.id || null,
    project: proj,
    dependencies: deps,
    links: (v.links || []).slice(0, 6),
  };
}

async function advisory(id) {
  if (DRY) { console.log(JSON.stringify({ dry_run: true, url: `${API}/advisories/${enc(id)}` }, null, 2)); return; }
  const a = await get(`${API}/advisories/${enc(id)}`);
  if (!a || a.__notfound) return { source: 'deps.dev', type: 'advisory', id, found: false };
  return {
    source: 'deps.dev', type: 'advisory', found: true, id: a.advisoryKey?.id || id,
    title: a.title, aliases: a.aliases || [], cves: (a.aliases || []).filter((x) => /^CVE-/i.test(x)),
    cvss3_score: a.cvss3Score, cvss3_vector: a.cvss3Vector, url: a.url,
  };
}

function parseHash(h) {
  const s = h.trim();
  if (/^[0-9a-fA-F]+$/.test(s)) {
    const t = { 32: 'MD5', 40: 'SHA1', 64: 'SHA256', 128: 'SHA512' }[s.length];
    if (t) return { type: t, b64: Buffer.from(s, 'hex').toString('base64') };
  }
  return { type: 'SHA256', b64: s }; // assume already base64 (SHA-256 is the common CTI case)
}

async function hash(h) {
  const { type, b64 } = parseHash(h);
  const url = `${API}/query?hash.type=${type}&hash.value=${enc(b64)}`;
  if (DRY) { console.log(JSON.stringify({ dry_run: true, hash_type: type, url }, null, 2)); return; }
  const r = await get(url);
  const results = (r && r.results) || [];
  return {
    source: 'deps.dev', type: 'hash', hash: h, hash_type: type, found: results.length > 0, match_count: results.length,
    matches: results.slice(0, 25).map((x) => ({
      system: x.version?.versionKey?.system, name: x.version?.versionKey?.name, version: x.version?.versionKey?.version,
    })),
  };
}

async function main() {
  const argv = process.argv.slice(2);
  DRY = argv.includes('--dry-run');
  const a = argv.filter((x) => !x.startsWith('--'));
  const cmd = a[0];
  let out;
  if (cmd === 'pkg' && a.length >= 3) out = await pkg(a[1], a[2], a[3]);
  else if (cmd === 'advisory' && a.length >= 2) out = await advisory(a[1]);
  else if (cmd === 'hash' && a.length >= 2) out = await hash(a[1]);
  else usage();
  if (!DRY && out !== undefined) console.log(JSON.stringify(out, null, 2));
}

main().catch((e) => die(e.message));
