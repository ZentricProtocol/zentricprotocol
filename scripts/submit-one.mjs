#!/usr/bin/env node
/**
 * submit-one.mjs <smithery|mcpso|glama|cursor>
 *
 * Opens ONE MCP registry's submission form in a visible Chromium with
 * a persistent profile, waits for the user to complete OAuth login if
 * needed, then fills every field and clicks Submit automatically.
 * Stays open after submit so the user can verify before closing.
 *
 * Run: node scripts/submit-one.mjs smithery
 */
import { chromium } from 'playwright';
import os from 'node:os';
import path from 'node:path';

const DATA = {
  name: 'Zentric Protocol',
  shortName: 'zentric-protocol-mcp',
  shortDescription:
    'Prompt injection + PII detection MCP server for AI agents. 22 signatures, 7 languages, ~23ms latency. Signed GDPR Art.30 audit reports.',
  longDescription:
    'Zentric Protocol is a prompt injection detection and PII redaction MCP server for AI agents and LLM applications. It exposes one tool, analyze_prompt, that scans every input against 22 injection signatures across 7 languages and 17 PII entity types (emails, phone numbers, IBANs, SSNs, NIF, CPF, CURP, and more) before the prompt reaches your model. Each call returns a deterministic verdict (CLEARED, ANONYMIZED, or BLOCKED), a SHA-256 hash, a UUID, and a UTC timestamp — suitable as a GDPR Art.30 record-of-processing entry. Mean server-side latency 23.4ms across 1M simulated requests. Free tier 2,000 req/mo.',
  githubUrl:
    'https://github.com/ZentricProtocol/zentricprotocol/tree/main/mcp-server',
  npmPackage: 'zentric-protocol-mcp',
  homepage: 'https://zentricprotocol.com',
  logoUrl: 'https://zentricprotocol.com/og.png',
  email: 'core@zentricprotocol.com',
  category: 'Security',
};

/* ── Per-registry handlers ─────────────────────────────────────────── */

async function tryFill(page, selectors, value, opts = {}) {
  for (const sel of selectors) {
    try {
      const loc = page.locator(sel).first();
      if ((await loc.count()) === 0) continue;
      if (!(await loc.isVisible({ timeout: 1500 }).catch(() => false))) continue;
      if (opts.select) {
        await loc.selectOption({ label: value }).catch(() => loc.selectOption(value));
      } else {
        await loc.fill(value, { timeout: 5000 });
      }
      console.log(`    ✓ filled via ${sel} → "${String(value).slice(0, 60)}${String(value).length > 60 ? '…' : ''}"`);
      return true;
    } catch { /* try next */ }
  }
  console.log(`    ✗ no selector matched for "${String(value).slice(0, 40)}…"`);
  return false;
}

async function clickFirst(page, selectors, label) {
  for (const sel of selectors) {
    try {
      const loc = page.locator(sel).first();
      if ((await loc.count()) === 0) continue;
      if (!(await loc.isVisible({ timeout: 1500 }).catch(() => false))) continue;
      await loc.click();
      console.log(`    ✓ clicked ${label || sel}`);
      return true;
    } catch { /* try next */ }
  }
  console.log(`    ✗ couldn't click ${label || selectors[0]}`);
  return false;
}

async function waitForLoginIfNeeded(page, formIndicators) {
  // Look for any of the formIndicators to determine the form is ready.
  // If none appear within 6s, assume we're on a login screen and poll
  // up to 10 minutes for them to appear (after the user logs in).
  const deadline = Date.now() + 6_000;
  while (Date.now() < deadline) {
    for (const sel of formIndicators) {
      const c = await page.locator(sel).count().catch(() => 0);
      if (c > 0) return false; // form visible, no login needed
    }
    await page.waitForTimeout(500);
  }
  console.log('  → form not detected within 6s — assuming login screen.');
  console.log('  → please complete OAuth login in the browser window now.');
  console.log('  → I will start filling automatically once the form appears (max wait 10 min).');
  const loginDeadline = Date.now() + 600_000;
  while (Date.now() < loginDeadline) {
    for (const sel of formIndicators) {
      const c = await page.locator(sel).count().catch(() => 0);
      if (c > 0) {
        console.log('  → form detected — proceeding to auto-fill.');
        await page.waitForTimeout(800);
        return true;
      }
    }
    await page.waitForTimeout(1500);
  }
  throw new Error('Timed out waiting for login + form (10 min).');
}

const HANDLERS = {
  smithery: {
    name: 'Smithery',
    url: 'https://smithery.ai/new',
    run: async (page) => {
      await waitForLoginIfNeeded(page, [
        'input[type="url"]',
        'input[placeholder*="github" i]',
        'input[name*="repo" i]',
        'input[name*="url" i]',
      ]);
      await tryFill(
        page,
        [
          'input[name*="repo" i]',
          'input[placeholder*="github" i]',
          'input[type="url"]',
          'input',
        ],
        DATA.githubUrl,
      );
      await page.waitForTimeout(800);
      await tryFill(page, ['input[name="name"]', 'input[placeholder*="name" i]'], DATA.name);
      await tryFill(
        page,
        ['textarea[name="description"]', 'textarea[placeholder*="description" i]', 'textarea'],
        DATA.shortDescription,
      );
      console.log('  → clicking Submit in 3s (Ctrl+C to abort)…');
      await page.waitForTimeout(3000);
      await clickFirst(
        page,
        [
          'button:has-text("Submit")',
          'button:has-text("Publish")',
          'button:has-text("Create")',
          'button[type="submit"]',
        ],
        'Submit',
      );
    },
  },

  mcpso: {
    name: 'mcp.so',
    url: 'https://mcp.so',
    run: async (page) => {
      console.log('  → opening mcp.so home — please log in first if prompted.');
      console.log('  → after login, click "Submit" or "Add Server" in the header.');
      console.log('  → I will detect the submit form and fill it automatically.');
      await waitForLoginIfNeeded(page, [
        'input[name="url"]',
        'input[name="name"]',
        'input[name="title"]',
        'textarea[name="description"]',
      ]);
      await tryFill(page, ['input[name="url"]', 'input[type="url"]'], DATA.githubUrl);
      await tryFill(page, ['input[name="name"]'], DATA.shortName);
      await tryFill(page, ['input[name="title"]'], DATA.name);
      await tryFill(
        page,
        ['textarea[name="description"]', 'input[name="description"]'],
        DATA.shortDescription,
      );
      await tryFill(page, ['input[name="avatar_url"]', 'input[name="avatar"]'], DATA.logoUrl);
      await tryFill(page, ['input[name="homepage"]'], DATA.homepage);
      await tryFill(page, ['input[name="author_name"]', 'input[name="author"]'], DATA.name);
      // Type select — try multiple shapes
      await tryFill(
        page,
        ['select[name="type"]'],
        'server',
        { select: true },
      ).catch(() => {});
      await tryFill(
        page,
        ['select[name="category"]'],
        DATA.category,
        { select: true },
      ).catch(() => {});
      console.log('  → clicking Submit in 3s (Ctrl+C to abort)…');
      await page.waitForTimeout(3000);
      await clickFirst(
        page,
        [
          'button:has-text("Submit")',
          'button:has-text("Publish")',
          'button[type="submit"]',
        ],
        'Submit',
      );
    },
  },

  glama: {
    name: 'Glama',
    url: 'https://glama.ai/mcp/servers/add',
    run: async (page) => {
      await waitForLoginIfNeeded(page, [
        'input[name*="repo" i]',
        'input[type="url"]',
        'textarea[name="description"]',
        'input[name="name"]',
      ]);
      await tryFill(
        page,
        ['input[name*="repo" i]', 'input[placeholder*="github" i]', 'input[type="url"]'],
        DATA.githubUrl,
      );
      await tryFill(page, ['input[name="name"]'], DATA.name);
      await tryFill(
        page,
        ['textarea[name="description"]', 'textarea'],
        DATA.shortDescription,
      );
      // Glama sometimes asks for a long description in a second textarea
      const textareas = await page.locator('textarea').count().catch(() => 0);
      if (textareas > 1) {
        const second = page.locator('textarea').nth(1);
        if (await second.isVisible().catch(() => false)) {
          await second.fill(DATA.longDescription).catch(() => {});
        }
      }
      await tryFill(page, ['input[name="homepage"]', 'input[name="website"]'], DATA.homepage);
      console.log('  → clicking Submit in 3s (Ctrl+C to abort)…');
      await page.waitForTimeout(3000);
      await clickFirst(
        page,
        [
          'button:has-text("Submit")',
          'button:has-text("Add")',
          'button:has-text("Publish")',
          'button[type="submit"]',
        ],
        'Submit',
      );
    },
  },

  cursor: {
    name: 'cursor.directory',
    url: 'https://www.cursor.directory/mcp/new',
    run: async (page) => {
      await waitForLoginIfNeeded(page, [
        'input[name="name"]',
        'textarea[name="description"]',
        'input[name="link"]',
      ]);
      await tryFill(page, ['input[name="name"]'], DATA.name);
      await tryFill(
        page,
        ['textarea[name="description"]', 'textarea'],
        DATA.shortDescription,
      );
      await tryFill(
        page,
        ['input[name="link"]', 'input[name="url"]', 'input[type="url"]'],
        DATA.githubUrl,
      );
      console.log('  → clicking Submit in 3s (Ctrl+C to abort)…');
      await page.waitForTimeout(3000);
      await clickFirst(
        page,
        [
          'button:has-text("Submit")',
          'button:has-text("Create")',
          'button:has-text("Publish")',
          'button[type="submit"]',
        ],
        'Submit',
      );
    },
  },
};

/* ── Main ──────────────────────────────────────────────────────────── */

async function main() {
  const which = (process.argv[2] || '').toLowerCase();
  const reg = HANDLERS[which];
  if (!reg) {
    console.error(`Usage: node scripts/submit-one.mjs <smithery|mcpso|glama|cursor>`);
    process.exit(1);
  }

  const profileDir = path.join(os.homedir(), '.zentric-mcp-submit-profile');
  console.log(`\n[${reg.name}] launching headed Chromium…`);
  console.log(`[${reg.name}] persistent profile: ${profileDir}`);
  console.log(`[${reg.name}] URL: ${reg.url}\n`);

  const ctx = await chromium.launchPersistentContext(profileDir, {
    headless: false,
    viewport: { width: 1280, height: 900 },
    args: ['--disable-blink-features=AutomationControlled'],
  });
  const page = ctx.pages()[0] || (await ctx.newPage());
  await page.goto(reg.url, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch((e) => {
    console.log(`  ⚠️  navigation issue: ${e.message}`);
  });

  console.log(`[${reg.name}] starting fill sequence…`);
  try {
    await reg.run(page);
    console.log(`[${reg.name}] submit click attempted.`);
  } catch (err) {
    console.log(`[${reg.name}] error: ${err.message}`);
  }

  console.log(
    `\n[${reg.name}] ✓ done. Browser will stay open for 90 seconds so you can verify the result.`,
  );
  console.log(`[${reg.name}] (close the window manually to skip the wait)`);
  // Resolve early if user closes the window
  await Promise.race([
    new Promise((r) => ctx.on('close', r)),
    page.waitForTimeout(90_000),
  ]);
  await ctx.close().catch(() => {});
  console.log(`[${reg.name}] exited.\n`);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
