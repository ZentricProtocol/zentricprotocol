/**
 * /api/playground/analyze
 *
 * Same-origin proxy for the public playground page. Holds the demo API key
 * server-side (env: ZENTRIC_API_KEY or ZENTRIC_DEMO_API_KEY), rate-limits per
 * IP, and STRIPS raw injection-signature IDs and PII entity types before
 * returning data to the browser — only human-readable category names leave
 * the server. The /v1/analyze endpoint is intentionally NOT called directly
 * from the browser so the key cannot be scraped from page source.
 */

const UPSTREAM = 'https://api.zentricprotocol.com/v1/analyze';

// Raw signature ID → human-readable category. Used to sanitize the upstream
// response. Language suffixes (_EN/_ES/_FR/...) collapse to the same category,
// and anything unknown becomes a generic label, so we never leak signature
// naming conventions to the public. (Engine v2 signature IDs.)
const SIGNATURE_CATEGORIES = {
  FAKE_SYSTEM_TOKEN: 'Fake System Marker',
  DELIMITER_INJECTION: 'Delimiter Injection',
  BASE64_PAYLOAD: 'Base64 Smuggling',
  PROMPT_LEAKAGE_REQUEST: 'Prompt Leakage',
  NESTED_INSTRUCTION: 'Nested Instruction',
  AUTHORITY_CLAIM: 'Authority Claim',
  DATA_EXFILTRATION: 'Data Exfiltration',
  INSTRUCTION_OVERRIDE: 'Instruction Override',
  ROLE_HIJACK: 'Role Manipulation',
  JAILBREAK_DAN: 'Jailbreak (DAN)',
  HYPOTHETICAL_FRAME: 'Hypothetical Framing',
  CONFIDENCE_MANIPULATION: 'Coercion / Compliance Pressure',
};

function categorizeSignature(sig) {
  if (SIGNATURE_CATEGORIES[sig]) return SIGNATURE_CATEGORIES[sig];
  const base = sig.replace(/_(EN|ES|FR|DE|PT|IT|NL|ZH|JA)$/, '');
  return SIGNATURE_CATEGORIES[base] || 'Anomalous pattern';
}

const PII_CATEGORIES = {
  EMAIL: 'Email Address',
  PHONE: 'Phone Number',
  CREDIT_CARD: 'Credit Card',
  IBAN: 'IBAN',
  IP_ADDRESS: 'IP Address',
  DATE_OF_BIRTH: 'Date of Birth',
  PASSPORT: 'Passport Number',
  NIF_NIE: 'Spanish NIF/NIE',
  SSN: 'U.S. SSN',
  CPF: 'Brazilian CPF',
  CURP: 'Mexican CURP',
  NHS_NUMBER: 'UK NHS Number',
};

// In-memory per-IP token bucket. Survives within a warm serverless instance,
// resets across cold starts. Imperfect but adds friction to scripted abuse.
const buckets = new Map();
const RATE_LIMIT = 20; // requests
const WINDOW_MS = 60_000; // per minute
const MAX_INPUT_BYTES = 4_096;

function clientIp(req) {
  const xfwd = req.headers['x-forwarded-for'];
  if (typeof xfwd === 'string' && xfwd.length > 0) return xfwd.split(',')[0].trim();
  return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
}

function checkRate(ip) {
  const now = Date.now();
  const b = buckets.get(ip);
  if (!b || now - b.windowStart > WINDOW_MS) {
    buckets.set(ip, { count: 1, windowStart: now });
    return { ok: true, remaining: RATE_LIMIT - 1 };
  }
  b.count += 1;
  if (b.count > RATE_LIMIT) {
    return { ok: false, retryAfter: Math.ceil((WINDOW_MS - (now - b.windowStart)) / 1000) };
  }
  return { ok: true, remaining: RATE_LIMIT - b.count };
}

function sanitize(result) {
  if (!result?.report) {
    return { verdict: result?.verdict ?? 'UNKNOWN' };
  }
  const sigs = result.report.integrity?.signatures_matched ?? [];
  const categoriesMatched = sigs.map(categorizeSignature);
  const piiEntities = (result.report.privacy?.entities ?? []).map((e) => ({
    category: PII_CATEGORIES[e.type] || 'Personal data',
    action: e.action ?? 'REDACTED', // v2 entities are always redacted; no per-entity action field
  }));

  let primary = categoriesMatched[0] || piiEntities[0]?.category || null;
  if (!primary) {
    primary = result.verdict === 'CLEARED' ? 'No threat detected' : 'Anomalous pattern';
  }

  return {
    verdict: result.verdict,
    primary_category: primary,
    categories_matched: categoriesMatched,
    pii_detected: result.report.privacy?.pii_detected === true,
    pii_entities: piiEntities,
    confidence: result.report.integrity?.confidence ?? null,
    latency_ms: result.report.latency_ms ?? result.latency_ms ?? null,
    report: {
      report_id: result.report.report_id,
      sha256: result.report.sha256,
      timestamp_utc: result.report.timestamp_utc,
    },
  };
}

async function readBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'string') {
      try {
        return JSON.parse(req.body);
      } catch {
        return { __parseError: true };
      }
    }
    return req.body;
  }
  return new Promise((resolve) => {
    let raw = '';
    let aborted = false;
    req.on('data', (chunk) => {
      if (aborted) return;
      raw += chunk;
      if (raw.length > MAX_INPUT_BYTES * 2) {
        aborted = true;
        req.destroy();
        resolve({ __tooLarge: true });
      }
    });
    req.on('end', () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve({ __parseError: true });
      }
    });
    req.on('error', () => resolve({ __parseError: true }));
  });
}

function send(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex');
  res.end(JSON.stringify(payload));
}

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }
  if (req.method !== 'POST') {
    return send(res, 405, { error: 'method_not_allowed', message: 'Use POST' });
  }

  const ip = clientIp(req);
  const rl = checkRate(ip);
  if (!rl.ok) {
    res.setHeader('Retry-After', String(rl.retryAfter));
    return send(res, 429, {
      error: 'rate_limit',
      message: `Slow down — the playground is rate-limited to ${RATE_LIMIT} requests per minute per IP. Get your own API key for higher limits.`,
      retry_after_seconds: rl.retryAfter,
    });
  }

  const body = await readBody(req);
  if (body?.__tooLarge) {
    return send(res, 413, { error: 'payload_too_large', message: 'Input exceeds playground cap.' });
  }
  if (body?.__parseError) {
    return send(res, 400, { error: 'invalid_body', message: 'Body must be valid JSON.' });
  }
  const input = body?.input;
  if (typeof input !== 'string' || !input.trim()) {
    return send(res, 400, { error: 'invalid_input', message: 'Provide a non-empty "input" string.' });
  }
  if (Buffer.byteLength(input, 'utf8') > MAX_INPUT_BYTES) {
    return send(res, 413, {
      error: 'input_too_large',
      message: `Playground caps inputs at ${MAX_INPUT_BYTES} bytes. Use the API directly for longer text.`,
    });
  }

  const key = process.env.ZENTRIC_API_KEY || process.env.ZENTRIC_DEMO_API_KEY;
  if (!key) {
    console.error('Playground: missing ZENTRIC_API_KEY env var');
    return send(res, 500, { error: 'server_misconfigured', message: 'Demo unavailable — see /quickstart for direct API access.' });
  }

  let upstreamRes;
  let upstreamBody;
  try {
    upstreamRes = await fetch(UPSTREAM, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${key}`,
        'Content-Type': 'application/json',
        'User-Agent': 'zentric-playground/1.0',
      },
      body: JSON.stringify({ input, modules: ['integrity', 'privacy'], options: { language: 'auto' } }),
    });
    const text = await upstreamRes.text();
    try {
      upstreamBody = text ? JSON.parse(text) : {};
    } catch {
      upstreamBody = { raw: text };
    }
  } catch (err) {
    console.error('Playground upstream error:', err?.code, err?.message);
    return send(res, 502, { error: 'upstream_failed', message: 'Could not reach the Zentric API.' });
  }

  if (!upstreamRes.ok) {
    return send(res, upstreamRes.status, {
      error: upstreamBody?.error || 'upstream_error',
      message: upstreamBody?.message || `Upstream returned ${upstreamRes.status}`,
    });
  }

  res.setHeader('X-RateLimit-Limit', String(RATE_LIMIT));
  res.setHeader('X-RateLimit-Remaining', String(rl.remaining));
  return send(res, 200, sanitize(upstreamBody));
}
