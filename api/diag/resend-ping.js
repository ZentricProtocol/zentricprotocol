/**
 * api/diag/resend-ping.js — TEMPORARY diagnostic endpoint.
 *
 * Tests the Resend API key in the deployed environment by sending a real
 * email to core@zentricprotocol.com. Returns the upstream HTTP status and
 * (truncated, key-redacted) error body. Never echoes the full key.
 *
 * Auth: shared single-use token in ?token=. Bad tokens get a generic 404
 * so the endpoint's existence isn't probeable.
 *
 * DELETE THIS FILE after diagnosis is complete.
 */
import crypto from 'node:crypto';

const DIAG_TOKEN = 'zp-diag-2026';
const RESEND_ENDPOINT = 'https://api.resend.com/emails';
const RE_KEY_PATTERN = /re_[A-Za-z0-9_]{6,}/g;

function tokenOk(provided) {
  if (typeof provided !== 'string') return false;
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(DIAG_TOKEN, 'utf8');
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function redactKey(s) {
  if (typeof s !== 'string') return s;
  return s.replace(RE_KEY_PATTERN, '[REDACTED_KEY]');
}

function send(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.end(JSON.stringify(payload));
}

function getToken(req) {
  if (req.query && typeof req.query.token === 'string') return req.query.token;
  try {
    const u = new URL(req.url, 'http://localhost');
    return u.searchParams.get('token');
  } catch {
    return null;
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return send(res, 405, { error: 'method_not_allowed', message: 'Use POST' });
  }

  if (!tokenOk(getToken(req))) {
    // Generic 404 so the endpoint's presence isn't discoverable.
    return send(res, 404, { error: 'not_found' });
  }

  const apiKey = process.env.RESEND_API_KEY;
  const keyPresent = typeof apiKey === 'string' && apiKey.length > 0;
  const keyPrefix = keyPresent ? apiKey.substring(0, 7) : null;
  const keyLength = keyPresent ? apiKey.length : 0;

  if (!keyPresent) {
    return send(res, 200, {
      ok: false,
      status: 0,
      resend_error: 'RESEND_API_KEY env var not set or empty in this deployment',
      key_present: false,
      key_prefix: null,
      key_length: 0,
    });
  }

  let resendStatus = 0;
  let resendBody = '';
  try {
    const upstream = await fetch(RESEND_ENDPOINT, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'zentric-diag/1.0',
      },
      body: JSON.stringify({
        from: 'Zentric Protocol <core@zentricprotocol.com>',
        to: 'core@zentricprotocol.com',
        subject: '[DIAG] Resend test',
        html: '<p>Diagnostic test from api/diag/resend-ping.js</p>',
      }),
    });
    resendStatus = upstream.status;
    resendBody = await upstream.text();
  } catch (err) {
    const msg = redactKey(String(err?.message || err)).slice(0, 200);
    console.error('Resend diag: fetch threw:', err?.code, redactKey(String(err?.message || '')));
    return send(res, 200, {
      ok: false,
      status: 0,
      resend_error: msg,
      key_present: true,
      key_prefix: keyPrefix,
      key_length: keyLength,
      stage: 'fetch_throw',
    });
  }

  const bodySafe = redactKey(resendBody || '').slice(0, 200);
  const ok = resendStatus >= 200 && resendStatus < 300;

  console.log(
    `Resend diag: status=${resendStatus} ok=${ok} key_prefix=${keyPrefix} key_length=${keyLength}`,
  );

  return send(res, 200, {
    ok,
    status: resendStatus,
    resend_error: ok ? null : bodySafe,
    key_present: true,
    key_prefix: keyPrefix,
    key_length: keyLength,
  });
}
