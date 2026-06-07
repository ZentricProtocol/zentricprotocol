/**
 * Zentric Protocol — Supabase Keepalive (Vercel Cron)
 *
 * Supabase free-tier projects are automatically PAUSED after 7 days with no
 * database activity. A paused database makes /v1/analyze return
 * 500 AUTH_LOOKUP_FAILED (the auth lookup can't reach Postgres), taking the
 * whole API, the MCP server and the public playground offline.
 *
 * This cron runs once a day and issues one trivial read against the database.
 * That single query counts as activity and keeps the project from ever
 * crossing the 7-day inactivity threshold.
 *
 * NOTE: This is a mitigation, not a guarantee. The robust fix for a product
 * sold to enterprise customers is Supabase Pro (no auto-pause). Keep this cron
 * even on Pro — it doubles as a cheap daily database health check.
 *
 * Security: Vercel sets `Authorization: Bearer <CRON_SECRET>` on scheduled
 * invocations. We reject anything whose header does not match.
 *
 * Environment variables required:
 *   SUPABASE_URL
 *   SUPABASE_SERVICE_ROLE_KEY
 *   CRON_SECRET
 */

import { getSupabase } from '../../lib/supabase.js';

export default async function handler(req, res) {
  const auth = req.headers.authorization || '';
  const expected = `Bearer ${process.env.CRON_SECRET}`;
  if (!process.env.CRON_SECRET || auth !== expected) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  let supabase;
  try {
    supabase = getSupabase();
  } catch (err) {
    console.error('[cron-keepalive] Supabase init failed:', err.message);
    return res.status(500).json({ error: 'server_misconfigured' });
  }

  // One cheap read = one unit of DB activity. HEAD + count avoids transferring
  // any row data; we only need the round-trip to hit Postgres.
  const startedAt = Date.now();
  const { error, count } = await supabase
    .from('free_api_keys')
    .select('id', { count: 'exact', head: true });

  if (error) {
    console.error('[cron-keepalive] query failed:', error.message);
    return res.status(500).json({ error: 'keepalive_failed', detail: error.message });
  }

  const latencyMs = Date.now() - startedAt;
  console.log(`[cron-keepalive] OK · ${latencyMs}ms · free_keys=${count ?? 'n/a'}`);
  return res.status(200).json({
    ok: true,
    db_latency_ms: latencyMs,
    free_keys: count ?? null,
    ran_at: new Date().toISOString(),
  });
}
