#!/usr/bin/env node
// tools/clis/hudsonrock.js - Hudson Rock Cavalier infostealer lookup (zero deps, Node >= 18)
// Usage: node hudsonrock.js <domain|email|ip> <value> [--dry-run]
//
// Free Cavalier OSINT endpoints need no key. If HUDSONROCK_API_KEY is set it is
// appended for the paid tier; absence is normal, not an error.

const https = require('https');

const API_KEY = process.env.HUDSONROCK_API_KEY;
const API_BASE = 'https://cavalier.hudsonrock.com/api/json/v2';

function die(msg, code = 1) {
  process.stderr.write(`error: ${msg}\n`);
  process.exit(code);
}

function usage() {
  process.stderr.write(
    'usage: hudsonrock.js <domain|email|ip> <value> [--dry-run]\n\n' +
    'Env: HUDSONROCK_API_KEY optional (free OSINT endpoints work without it).\n'
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

function pathFor(type, value) {
  const enc = encodeURIComponent(value);
  if (type === 'domain') return `/osint-tools/search-by-domain?domain=${enc}`;
  if (type === 'email') return `/osint-tools/search-by-email?email=${enc}`;
  if (type === 'ip') return `/osint-tools/search-by-ip?ip=${enc}`;
  usage();
}

// Free endpoints return credentials already masked by Hudson Rock; passed through as-is.
function trimStealer(s) {
  return {
    date_compromised: s.date_compromised,
    computer_name: s.computer_name,
    operating_system: s.operating_system,
    malware_path: s.malware_path,
    antiviruses: s.antiviruses,
    ip: s.ip,
    total_corporate_services: s.total_corporate_services,
    total_user_services: s.total_user_services,
    top_logins: s.top_logins,
    top_passwords: s.top_passwords,
  };
}

function summarise(type, value, resp) {
  const base = { source: 'hudsonrock', indicator: value, type, query_time: new Date().toISOString() };

  if (type === 'domain') {
    const data = resp.data || {};
    const total = resp.total || 0;
    return {
      ...base,
      found: total > 0,
      compromised_machines: total,          // machines with a credential for this domain
      total_stealers_in_db: resp.totalStealers,
      employees_compromised: resp.employees,
      users_compromised: resp.users,
      third_parties_compromised: resp.third_parties,
      top_employee_urls: (data.employees_urls || []).slice(0, 10),
      top_client_urls: (data.clients_urls || []).slice(0, 10),
    };
  }

  // email / ip: { message, stealers: [...], total_corporate_services, total_user_services }
  const stealers = Array.isArray(resp.stealers) ? resp.stealers : [];
  return {
    ...base,
    found: stealers.length > 0,
    stealer_count: stealers.length,
    message: resp.message,
    total_corporate_services: resp.total_corporate_services,
    total_user_services: resp.total_user_services,
    stealers: stealers.slice(0, 15).map(trimStealer),
  };
}

async function main() {
  const argv = process.argv.slice(2);
  const dryRun = argv.includes('--dry-run');
  const args = argv.filter((a) => !a.startsWith('--'));
  if (args.length < 2) usage();
  const [type, value] = args;
  if (!['domain', 'email', 'ip'].includes(type)) usage();

  let url = API_BASE + pathFor(type, value);
  if (API_KEY) url += `${url.includes('?') ? '&' : '?'}api-key=${encodeURIComponent(API_KEY)}`;
  const headers = { Accept: 'application/json' };

  if (dryRun) {
    const shown = API_KEY ? url.replace(encodeURIComponent(API_KEY), '<redacted>') : url;
    console.log(JSON.stringify({ dry_run: true, method: 'GET', url: shown, key: API_KEY ? '<set>' : '<unset, free tier>' }, null, 2));
    return;
  }

  const resp = await get(url, headers);
  console.log(JSON.stringify(summarise(type, value, resp), null, 2));
}

main().catch((e) => die(e.message));
