#!/usr/bin/env node
// tools/clis/circl-onion.js - CIRCL AIL onion-lookup (zero deps, Node >= 18)
// Usage: node circl-onion.js onion <address> [--dry-run]
//
// No key. Returns first/last seen, tags, titles, languages and any crypto
// addresses AIL extracted. An empty object ({}) means the onion is unknown.

const https = require('https');

const API_BASE = 'https://onion.ail-project.org';

function die(msg, code = 1) {
  process.stderr.write(`error: ${msg}\n`);
  process.exit(code);
}

function usage() {
  process.stderr.write(
    'usage: circl-onion.js onion <address> [--dry-run]\n\n' +
    'No API key required. Accepts a bare .onion host or a full onion URL.\n'
  );
  process.exit(3);
}

function get(url, headers) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        if (res.statusCode === 429) return reject(new Error('rate limited (429)'));
        if (res.statusCode >= 400) return reject(new Error(`HTTP ${res.statusCode}: ${body.slice(0, 300)}`));
        try { resolve(JSON.parse(body)); } catch { reject(new Error(`invalid JSON: ${body.slice(0, 300)}`)); }
      });
    }).on('error', reject);
  });
}

function normalise(addr) {
  let a = String(addr).trim().toLowerCase();
  a = a.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  return a;
}

// Pull any bitcoin/crypto address fields AIL may return under varying key names.
function cryptoAddrs(resp) {
  const out = {};
  for (const [k, v] of Object.entries(resp)) {
    if (/bitcoin|btc|monero|xmr|ethereum|crypto/i.test(k) && v && (Array.isArray(v) ? v.length : true)) {
      out[k] = v;
    }
  }
  return out;
}

async function main() {
  const argv = process.argv.slice(2);
  const dryRun = argv.includes('--dry-run');
  const args = argv.filter((a) => !a.startsWith('--'));
  if (args.length < 2 || args[0] !== 'onion') usage();

  const addr = normalise(args[1]);
  if (!/\.onion$/.test(addr)) die(`not a .onion address: ${addr}`, 3);

  const url = `${API_BASE}/api/lookup/${encodeURIComponent(addr)}`;
  const headers = { Accept: 'application/json' };

  if (dryRun) {
    console.log(JSON.stringify({ dry_run: true, method: 'GET', url }, null, 2));
    return;
  }

  const resp = (await get(url, headers)) || {};
  const seen = !!(resp.id || resp.first_seen || resp.last_seen);
  const crypto = cryptoAddrs(resp);
  const titles = (resp.titles || (resp.title ? [resp.title] : [])).slice(0, 10);

  const out = {
    source: 'circl-onion',
    indicator: addr,
    type: 'onion',
    query_time: new Date().toISOString(),
    seen,
    first_seen: resp.first_seen,
    last_seen: resp.last_seen,
    last_check: resp.last_check,
    languages: resp.languages,
    ...(titles.length ? { titles } : {}),
    tags: resp.tags,
    ...(Object.keys(crypto).length ? { crypto_addresses: crypto } : {}),
  };

  console.log(JSON.stringify(out, null, 2));
}

main().catch((e) => die(e.message));
