/**
 * Zentric Protocol — Monthly Usage Reset (Vercel Cron)
 *
 * Triggered by Vercel Cron at 00:05 UTC on the 1st of every month.
 * Resets `requests_this_month` to 0 on api_keys and free_api_keys.
 *
 * Security: Vercel automatically sets `Authorization: Bearer <CRON_SECRET>` on
 * scheduled cron invocations. We reject any request whose header does not match.
 *
 * Environment variables required:
 *   SUPABASE_URL
 *   SUPABASE_SERVICE_ROLE_KEY
 *   CRON_SECRET               — set to a long random string; same value goes
 *                                in Vercel project settings as the cron secret.
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
    console.error('[cron-reset] Supabase init failed:', err.message);
    return res.status(500).json({ error: 'server_misconfigured' });
  }

  const { data, error } = await supabase.rpc('reset_monthly_usage');
  if (error) {
    console.error('[cron-reset] RPC failed:', error.message);
    return res.status(500).json({ error: 'reset_failed', detail: error.message });
  }

  const result = Array.isArray(data) ? data[0] : data;
  console.log('[cron-reset] OK', result);
  return res.status(200).json({ ok: true, ...result, ran_at: new Date().toISOString() });
}
