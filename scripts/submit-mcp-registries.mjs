#!/usr/bin/env node
/**
 * submit-mcp-registries.mjs — semi-automated submission harness for the
 * MCP registries that require an OAuth/browser session.
 *
 * What it does:
 *   - Launches a *persistent* Chromium profile in ~/.zentric-mcp-submit-profile
 *     so your GitHub session for each site is reused between runs.
 *   - Opens each registry's submission form one at a time.
 *   - Auto-fills every field with the canonical Zentric Protocol data.
 *   - Stops at "Submit" — you read it, click Submit, then press Enter
 *     in this terminal to advance to the next registry.
 *
 * What it does NOT do:
 *   - It does not click Submit for you (deliberately — you review the
 *     filled-in fields and the OAuth consent screen yourself).
 *   - It does not store any credentials in this script. Login state
 *     lives only in the persistent Chromium profile on your disk.
 *
 * Usage:
 *   cd ~/Downloads/zentric-protocol
 *   npx playwright install chromium     # one-time
 *   node scripts/submit-mcp-registries.mjs
 *
 * If @playwright/test is not installed in the project root, run:
 *   npm install -D playwright
 * first.
 */

import { chromium } from 'playwright';
import readline from 'node:readline';
import os from 'node:os';
import path from 'node:path';

// ── Canonical data (single source of truth for every form) ─────────
const DATA = {
  name: 'Zentric Protocol',
  shortName: 'zentric-protocol-mcp',
  description:
    'Prompt injection detection and PII redaction for LLM apps and agent pipelines. Deterministic, pre-LLM, sub-25ms. GDPR Art.30 compliant audit reports.',
  shortDescription:
    'Prompt injection + PII detection MCP server. 22 signatures, 7 languages, ~23ms, signed audit reports.',
  githubUrl:
    'https://github.com/ZentricProtocol/zentricprotocol/tree/main/mcp-server',
  npmPackage: 'zentric-protocol-mcp',
  homepage: 'https://zentricprotocol.com',
  logoUrl: 'https://zentricprotocol.com/og.png',
  email: 'core@zentricprotocol.com',
  categoryFallback: 'Other',
  categorySecurity: 'Security',
};

const REGISTRIES = [
  {
    name: 'Smithery',
    url: 'https://smithery.ai/new',
    fields: [
      { kind: 'text', label: 'GitHub repository URL', value: DATA.githubUrl, selectors: ['input[name*="repo" i]', 'input[placeholder*="github" i]', 'input[type="url"]'] },
      { kind: 'text', label: 'Name', value: DATA.name, selectors: ['input[name="name"]', 'input[placeholder*="name" i]'] },
      { kind: 'text', label: 'Description', value: DATA.shortDescription, selectors: ['textarea[name="description"]', 'textarea[placeholder*="description" i]'] },
    ],
    requiresLogin: 'GitHub OAuth',
  },
  {
    name: 'mcp.so',
    url: 'https://mcp.so/submit',
    fields: [
      { kind: 'text', label: 'URL', value: DATA.githubUrl, selectors: ['input[name="url"]', 'input[type="url"]'] },
      { kind: 'text', label: 'Name', value: DATA.shortName, selectors: ['input[name="name"]'] },
      { kind: 'text', label: 'Title', value: DATA.name, selectors: ['input[name="title"]'] },
      { kind: 'text', label: 'Description', value: DATA.shortDescription, selectors: ['textarea[name="description"]', 'input[name="description"]'] },
    ],
    requiresLogin: 'mcp.so login (GitHub OAuth)',
  },
  {
    name: 'Glama',
    url: 'https://glama.ai/mcp/servers/add',
    fields: [
      { kind: 'text', label: 'Repository URL', value: DATA.githubUrl, selectors: ['input[name*="repo" i]', 'input[type="url"]', 'input[placeholder*="github" i]'] },
      { kind: 'text', label: 'Name', value: DATA.name, selectors: ['input[name="name"]'] },
      { kind: 'text', label: 'Description', value: DATA.shortDescription, selectors: ['textarea[name="description"]', 'textarea'] },
    ],
    requiresLogin: 'GitHub OAuth',
  },
  {
    name: 'mcpservers.org',
    url: 'https://mcpservers.org/submit',
    fields: [
      { kind: 'text', label: 'Server Name', value: DATA.shortName, selectors: ['input[name="name"]'] },
      { kind: 'text', label: 'Short Description', value: DATA.description, selectors: ['input[name="description"]', 'textarea[name="description"]'] },
      { kind: 'text', label: 'Link', value: DATA.githubUrl, selectors: ['input[name="url"]', 'input[type="url"]'] },
      { kind: 'select', label: 'Category', value: 'Other', selectors: ['select[name="category"]'] },
      { kind: 'text', label: 'Contact Email', value: DATA.email, selectors: ['input[name="email"]', 'input[type="email"]'] },
    ],
    requiresLogin: 'none — anonymous form',
  },
  {
    name: 'cursor.directory',
    url: 'https://www.cursor.directory/mcp/new',
    fields: [
      { kind: 'text', label: 'Name', value: DATA.name, selectors: ['input[name="name"]'] },
      { kind: 'text', label: 'Description', value: DATA.shortDescription, selectors: ['textarea[name="description"]'] },
      { kind: 'text', label: 'Link', value: DATA.githubUrl, selectors: ['input[name="link"]', 'input[name="url"]'] },
    ],
    requiresLogin: 'Cursor / GitHub OAuth',
  },
];

function pause(prompt) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(prompt, (a) => { rl.close(); resolve(a); }));
}

async function fillField(page, field) {
  for (const sel of field.selectors) {
    const loc = page.locator(sel).first();
    try {
      if ((await loc.count()) === 0) continue;
      if (!(await loc.isVisible({ timeout: 800 }).catch(() => false))) continue;
      if (field.kind === 'select') {
        await loc.selectOption({ label: field.value }).catch(() => loc.selectOption(field.value));
      } else {
        await loc.fill(field.value);
      }
      return true;
    } catch { /* try next selector */ }
  }
  return false;
}

async function handleRegistry(context, reg) {
  console.log('\n────────────────────────────────────────────────────────');
  console.log(`  ${reg.name}  ·  ${reg.url}`);
  console.log(`  Login required: ${reg.requiresLogin}`);
  console.log('────────────────────────────────────────────────────────');

  const page = await context.newPage();
  await page.goto(reg.url, { waitUntil: 'domcontentloaded' }).catch((e) => {
    console.log(`  ⚠️  Could not open page: ${e.message}`);
  });
  await page.waitForTimeout(1200); // let SPAs hydrate

  if (reg.requiresLogin !== 'none — anonymous form') {
    await pause(
      `  → If a login screen is showing, log in now.\n` +
      `    Press Enter once you're on the actual submission form  `,
    );
  }

  let filled = 0;
  for (const field of reg.fields) {
    const ok = await fillField(page, field);
    if (ok) {
      console.log(`  ✓ ${field.label.padEnd(22)} → "${field.value.slice(0, 60)}${field.value.length > 60 ? '…' : ''}"`);
      filled++;
    } else {
      console.log(`  ✗ ${field.label.padEnd(22)} — selector did not match; fill manually`);
    }
  }
  console.log(`  ${filled}/${reg.fields.length} fields auto-filled.`);

  await pause(`  → Review the page, click the Submit button, then press Enter to continue.  `);
  await page.close();
}

async function main() {
  const profileDir = path.join(os.homedir(), '.zentric-mcp-submit-profile');
  console.log(`\nUsing persistent Chromium profile: ${profileDir}`);
  console.log('(Sessions for each registry are remembered between runs.)\n');

  const context = await chromium.launchPersistentContext(profileDir, {
    headless: false,
    viewport: { width: 1280, height: 900 },
  });

  console.log('Submitting Zentric Protocol to MCP registries:');
  console.log(`  • name:        ${DATA.name}`);
  console.log(`  • github url:  ${DATA.githubUrl}`);
  console.log(`  • npm package: ${DATA.npmPackage}`);
  console.log(`  • homepage:    ${DATA.homepage}`);

  for (const reg of REGISTRIES) {
    try {
      await handleRegistry(context, reg);
    } catch (err) {
      console.log(`  ⚠️  ${reg.name} failed: ${err.message}`);
      const answer = await pause('  Continue to next registry? [Y/n]  ');
      if (answer.trim().toLowerCase().startsWith('n')) break;
    }
  }

  console.log('\nAll done. Close the browser window when ready.');
  await pause('\nPress Enter to exit the script (Chromium will close)…  ');
  await context.close();
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
