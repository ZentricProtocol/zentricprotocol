#!/usr/bin/env node
/**
 * registry-status.mjs — checks every major MCP registry for the
 * Zentric Protocol listing. Use as a one-shot or with --watch to
 * poll continuously through launch week.
 *
 * Usage:
 *   node scripts/registry-status.mjs              # single check
 *   node scripts/registry-status.mjs --watch      # loop every 5 min
 *   node scripts/registry-status.mjs --watch=60   # loop every 60 sec
 *   node scripts/registry-status.mjs --json       # machine-readable
 *
 * Exit codes (one-shot mode):
 *   0  all registries live
 *   1  one or more not yet indexed
 *   2  fatal error (network, etc.)
 *
 * Zero runtime dependencies — pure node + fetch.
 */

const NEEDLES = {
  npm: 'zentric-protocol-mcp',
  registryId: 'io.github.ZentricProtocol/zentric-protocol-mcp',
  brand: 'Zentric Protocol',
  // For HTML grep — case-insensitive substring match on any of these:
  htmlHints: ['zentric-protocol-mcp', 'zentric protocol', 'ZentricProtocol/zentricprotocol'],
};

const PR_NUMBER = 6478;
const PR_REPO = 'punkpeye/awesome-mcp-servers';

// Real-browser UA — many registries (PulseMCP, Smithery) gate requests
// from non-browser User-Agents via Cloudflare.
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const HEADERS = {
  'User-Agent': UA,
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
};
const TIMEOUT_MS = 15_000;

function htmlHas(body) {
  if (typeof body !== 'string' || body.length === 0) return false;
  const hay = body.toLowerCase();
  return NEEDLES.htmlHints.some((n) => hay.includes(n.toLowerCase()));
}

async function safeFetch(url, options = {}) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), options.timeout ?? TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: HEADERS,
      redirect: 'follow',
      signal: ctl.signal,
      ...options,
    });
    const text = await res.text();
    return { ok: res.ok, status: res.status, body: text, url: res.url };
  } catch (err) {
    return { ok: false, status: 0, body: '', error: err.message };
  } finally {
    clearTimeout(t);
  }
}

/* ── Registry checkers ─────────────────────────────────────────────── */

async function checkOfficial() {
  const r = await safeFetch(
    `https://registry.modelcontextprotocol.io/v0/servers?search=zentric`,
  );
  if (!r.ok) return fail(r);
  try {
    const data = JSON.parse(r.body);
    // Match the LATEST entry, not just the first
    const latest = (data.servers || [])
      .filter((s) => s.server?.name === NEEDLES.registryId)
      .find((s) => s._meta?.['io.modelcontextprotocol.registry/official']?.isLatest === true);
    if (latest) {
      const v = latest.server.version;
      const status = latest._meta['io.modelcontextprotocol.registry/official'].status;
      return live(`v${v} · ${status} · isLatest`);
    }
    // Fall back: any version present is acceptable but flag as stale
    const any = (data.servers || []).find((s) => s.server?.name === NEEDLES.registryId);
    if (any) return pending(`v${any.server.version} present but not isLatest`);
    return pending('not found in /v0/servers');
  } catch {
    return fail(r, 'unparseable JSON');
  }
}

async function checkNpm() {
  const r = await safeFetch(`https://registry.npmjs.org/${NEEDLES.npm}`);
  if (!r.ok) return r.status === 404 ? pending('404 — not published') : fail(r);
  try {
    const data = JSON.parse(r.body);
    const v = data['dist-tags']?.latest;
    return v ? live(`v${v}`) : pending('no dist-tags.latest');
  } catch {
    return fail(r, 'unparseable JSON');
  }
}

async function checkPulseMCP() {
  // PulseMCP doesn't expose a public JSON API; scrape search page.
  const r = await safeFetch(
    `https://www.pulsemcp.com/servers?q=${encodeURIComponent(NEEDLES.npm)}`,
  );
  if (!r.ok) return fail(r);
  return htmlHas(r.body) ? live('found in search') : pending('not yet indexed');
}

async function checkMcpServersOrg() {
  // Index page lists all servers in HTML. Also try a direct slug.
  const slug = await safeFetch(`https://mcpservers.org/server/${NEEDLES.npm}`);
  if (slug.ok && htmlHas(slug.body)) return live('direct page live');
  const home = await safeFetch(`https://mcpservers.org/`);
  if (home.ok && htmlHas(home.body)) return live('found on home');
  return pending('not yet published (free-tier review)');
}

async function checkSmithery() {
  const url = `https://smithery.ai/server/${encodeURIComponent(NEEDLES.registryId)}`;
  const r = await safeFetch(url);
  if (r.status === 200 && htmlHas(r.body)) return live('listed');
  return pending(`HTTP ${r.status}`);
}

async function checkMcpSo() {
  // mcp.so resolves /server/<slug> for ANY slug — a real listing has a
  // non-empty <title> like "Zentric Protocol - MCP Server"; a missing
  // listing renders "- MCP Server" (empty name before the dash).
  const r = await safeFetch(`https://mcp.so/server/${NEEDLES.npm}`);
  if (!r.ok) return fail(r);
  const title = (r.body.match(/<title>([^<]*)<\/title>/) || [, ''])[1].trim();
  const isPlaceholder = /^-\s*MCP Server/i.test(title) || title === '' || title === '- MCP Server';
  if (!isPlaceholder && /zentric/i.test(title)) {
    return live(`title="${title}"`);
  }
  // Search fallback
  const search = await safeFetch(
    `https://mcp.so/server-list?q=${encodeURIComponent(NEEDLES.npm)}`,
  );
  if (search.ok && /<a [^>]*href="\/server\/zentric-protocol-mcp"/i.test(search.body)) {
    return live('listed in search results');
  }
  return pending(`page is placeholder (title="${title}")`);
}

async function checkGlama() {
  const r = await safeFetch(
    `https://glama.ai/mcp/servers?query=${encodeURIComponent(NEEDLES.npm)}`,
  );
  if (!r.ok) return fail(r);
  // A real Glama listing renders as <a href="/mcp/servers/<owner>/<repo>/...">
  // The search page itself echoes the query as self-referential links
  // (/mcp/connectors?query=..., etc.) — exclude those.
  const matches = [...r.body.matchAll(/<a [^>]*href="(\/mcp\/servers\/[^"?]+)"/gi)];
  const realResult = matches.find(
    (m) => /zentric/i.test(m[1]) && !m[1].includes('?'),
  );
  if (realResult) return live(`/mcp${realResult[1]}`);
  return pending('no result link in search page');
}

async function checkCursorDirectory() {
  const r = await safeFetch(`https://www.cursor.directory/mcp`);
  if (!r.ok) return fail(r);
  return htmlHas(r.body) ? live('found on /mcp index') : pending('not yet indexed');
}

async function checkPunkpeyePR() {
  const r = await safeFetch(
    `https://api.github.com/repos/${PR_REPO}/pulls/${PR_NUMBER}`,
    { headers: { ...HEADERS, Accept: 'application/vnd.github+json' } },
  );
  if (!r.ok) return fail(r);
  try {
    const pr = JSON.parse(r.body);
    if (pr.merged) return live(`merged ${pr.merged_at}`);
    if (pr.state === 'open') return pending(`PR #${PR_NUMBER} open`);
    return pending(`PR ${pr.state}`);
  } catch {
    return fail(r, 'unparseable JSON');
  }
}

/* ── Result helpers ─────────────────────────────────────────────────── */

function live(detail) { return { state: 'live', detail }; }
function pending(detail) { return { state: 'pending', detail }; }
function fail(r, msg) {
  return { state: 'error', detail: msg || r.error || `HTTP ${r.status}` };
}

const REGISTRIES = [
  { name: 'Official MCP Registry', check: checkOfficial },
  { name: 'npm', check: checkNpm },
  { name: 'PulseMCP', check: checkPulseMCP },
  { name: 'mcpservers.org', check: checkMcpServersOrg },
  { name: 'Smithery', check: checkSmithery },
  { name: 'mcp.so', check: checkMcpSo },
  { name: 'Glama', check: checkGlama },
  { name: 'cursor.directory', check: checkCursorDirectory },
  { name: 'punkpeye PR #6478', check: checkPunkpeyePR },
];

/* ── Render ─────────────────────────────────────────────────────────── */

function pad(s, n) { return (s + ' '.repeat(n)).slice(0, n); }

function renderHuman(results) {
  const icon = { live: '✓', pending: '○', error: '✗' };
  const color = { live: '\x1b[32m', pending: '\x1b[33m', error: '\x1b[31m' };
  const reset = '\x1b[0m';
  const lines = results.map(
    (r) => `  ${color[r.state]}${icon[r.state]}${reset}  ${pad(r.name, 26)} ${pad(r.state, 8)} ${r.detail}`,
  );
  return lines.join('\n');
}

function renderSummary(results) {
  const live = results.filter((r) => r.state === 'live').length;
  const total = results.length;
  return `\n  ${live}/${total} live`;
}

/* ── Main loop ──────────────────────────────────────────────────────── */

async function runOnce() {
  const settled = await Promise.allSettled(
    REGISTRIES.map(async (reg) => ({ name: reg.name, ...(await reg.check()) })),
  );
  return settled.map((r) =>
    r.status === 'fulfilled' ? r.value : { name: '?', state: 'error', detail: String(r.reason) },
  );
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function main() {
  const args = process.argv.slice(2);
  const json = args.includes('--json');
  const watchArg = args.find((a) => a.startsWith('--watch'));
  const watchSec = watchArg
    ? parseInt(watchArg.split('=')[1] || '300', 10)
    : null;

  do {
    const results = await runOnce();
    if (json) {
      console.log(JSON.stringify({ at: new Date().toISOString(), results }, null, 2));
    } else {
      if (watchSec) process.stdout.write('\x1b[2J\x1b[H'); // clear screen in watch mode
      console.log(`\nZentric Protocol — MCP registry status  ·  ${new Date().toISOString()}\n`);
      console.log(renderHuman(results));
      console.log(renderSummary(results));
      if (watchSec) console.log(`  next check in ${watchSec}s · ctrl+c to stop`);
    }
    if (watchSec) await sleep(watchSec * 1000);
  } while (watchSec);

  const allLive = (await runOnce()).every((r) => r.state === 'live');
  process.exit(allLive ? 0 : 1);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(2);
});
