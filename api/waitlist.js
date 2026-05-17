// api/waitlist.js — Vercel Serverless Function
// PLG flow: email submitted → API key generated → welcome email sent instantly

import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';

// ---------------------------------------------------------------------------
// IP rate limiter — prevents bulk account creation to abuse the free tier.
// Allows 3 signups per IP per hour. In-memory per Vercel instance; sufficient
// for burst protection. For distributed abuse, upgrade to Upstash Redis.
// ---------------------------------------------------------------------------
const IP_WINDOW_MS   = 60 * 60 * 1000; // 1 hour
const IP_MAX_SIGNUPS = 3;
const ipSignupMap    = new Map(); // ip → { count, windowStart }

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket?.remoteAddress ?? 'unknown';
}

function checkIPRateLimit(ip) {
  const now    = Date.now();
  const record = ipSignupMap.get(ip);

  if (!record || now - record.windowStart > IP_WINDOW_MS) {
    ipSignupMap.set(ip, { count: 1, windowStart: now });
    return { allowed: true };
  }

  if (record.count >= IP_MAX_SIGNUPS) {
    const resetInMinutes = Math.ceil((IP_WINDOW_MS - (now - record.windowStart)) / 60000);
    return { allowed: false, resetInMinutes };
  }

  record.count += 1;
  return { allowed: true };
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const FREE_TIER_LIMIT = 2000;

function generateApiKey() {
  const random = crypto.randomBytes(24).toString('hex');
  return `zp_live_${random}`;
}

function hashKey(rawKey) {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

function getMonthBucket() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

async function sendWelcomeEmail(email, apiKey) {
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'Zentric Protocol <core@zentricprotocol.com>',
      to: email,
      subject: 'Your Zentric Protocol API key — 2,000 free requests',
      html: `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="dark light">
  <meta name="supported-color-schemes" content="dark light">
  <title>Your Zentric Protocol API key</title>
</head>
<body style="margin:0;padding:0;background:#0A0A0A;color:#F5F5F5;font-family:-apple-system,BlinkMacSystemFont,'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#0A0A0A;padding:48px 24px;">
    <tr>
      <td align="center" style="background:#0A0A0A;">
        <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;width:100%;background:#0A0A0A;">

          <!-- HEADER: logo mark + wordmark -->
          <tr>
            <td style="background:#0A0A0A;padding:0 0 40px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
                <tr>
                  <td style="background:#0A0A0A;vertical-align:middle;padding:0 12px 0 0;line-height:0;">
                    <svg width="22" height="22" viewBox="0 0 1000 1000" xmlns="http://www.w3.org/2000/svg" style="display:block;">
                      <polygon points="260,84 740,84 980,500 911,620 512,620 731,240 170,240" fill="#F5F5F5"/>
                      <polygon points="740,916 260,916 20,500 89,380 488,380 269,760 830,760" fill="#F5F5F5"/>
                    </svg>
                  </td>
                  <td style="background:#0A0A0A;vertical-align:middle;">
                    <span style="font-family:Menlo,Monaco,Consolas,'Courier New',Courier,monospace;font-size:12px;font-weight:700;letter-spacing:0.22em;color:#F5F5F5;text-transform:uppercase;">ZENTRIC&nbsp;PROTOCOL</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- HERO -->
          <tr>
            <td style="background:#0A0A0A;padding:0 0 28px;border-bottom:1px solid rgba(245,245,245,0.08);">
              <h1 style="margin:0 0 14px;font-family:-apple-system,BlinkMacSystemFont,'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:32px;font-weight:800;color:#F5F5F5;letter-spacing:-0.04em;line-height:1.04;">
                Your API key is ready.
              </h1>
              <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:15px;color:rgba(245,245,245,0.6);line-height:1.6;">
                2,000 free requests. No credit card. Save this key — it won't be shown again.
              </p>
            </td>
          </tr>

          <!-- API KEY -->
          <tr>
            <td style="background:#0A0A0A;padding:28px 0;border-bottom:1px solid rgba(245,245,245,0.08);">
              <p style="margin:0 0 10px;font-family:Menlo,Monaco,Consolas,'Courier New',Courier,monospace;font-size:10px;font-weight:600;letter-spacing:0.22em;color:rgba(245,245,245,0.4);text-transform:uppercase;">// Your API Key</p>
              <div style="background:rgba(245,245,245,0.025);border:1px solid rgba(245,245,245,0.12);border-radius:6px;padding:16px 18px;">
                <code style="font-family:Menlo,Monaco,Consolas,'Courier New',Courier,monospace;font-size:13px;color:#00FFC2;word-break:break-all;letter-spacing:0.01em;">${apiKey}</code>
              </div>
            </td>
          </tr>

          <!-- FIRST CALL -->
          <tr>
            <td style="background:#0A0A0A;padding:28px 0;border-bottom:1px solid rgba(245,245,245,0.08);">
              <p style="margin:0 0 10px;font-family:Menlo,Monaco,Consolas,'Courier New',Courier,monospace;font-size:10px;font-weight:600;letter-spacing:0.22em;color:rgba(245,245,245,0.4);text-transform:uppercase;">// Make your first call</p>
              <p style="margin:0 0 8px;font-family:Menlo,Monaco,Consolas,'Courier New',Courier,monospace;font-size:10px;color:rgba(245,245,245,0.35);letter-spacing:0.12em;">// Option 1: Via MCP (recommended for Claude Desktop / Cursor)</p>
              <div style="background:rgba(245,245,245,0.025);border:1px solid rgba(245,245,245,0.12);border-radius:6px;padding:16px 18px;margin-bottom:16px;">
                <pre style="margin:0;font-family:Menlo,Monaco,Consolas,'Courier New',Courier,monospace;font-size:12px;color:rgba(245,245,245,0.85);line-height:1.7;white-space:pre-wrap;word-break:break-all;">// Add to your claude_desktop_config.json:

{
  "mcpServers": {
    "zentric-protocol": {
      "command": "npx",
      "args": ["zentric-protocol-mcp"],
      "env": { "ZENTRIC_API_KEY": "${apiKey}" }
    }
  }
}</pre>
              </div>
              <p style="margin:0 0 8px;font-family:Menlo,Monaco,Consolas,'Courier New',Courier,monospace;font-size:10px;color:rgba(245,245,245,0.35);letter-spacing:0.12em;">// Option 2: Direct API</p>
              <div style="background:rgba(245,245,245,0.025);border:1px solid rgba(245,245,245,0.12);border-radius:6px;padding:16px 18px;">
                <pre style="margin:0;font-family:Menlo,Monaco,Consolas,'Courier New',Courier,monospace;font-size:12px;color:rgba(245,245,245,0.85);line-height:1.7;white-space:pre-wrap;word-break:break-all;">curl -X POST https://api.zentricprotocol.com/v1/analyze \\
  -H "Authorization: Bearer ${apiKey}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "input": "your user input here",
    "modules": ["integrity", "privacy"]
  }'</pre>
              </div>
            </td>
          </tr>

          <!-- WHAT EACH REQUEST RETURNS -->
          <tr>
            <td style="background:#0A0A0A;padding:28px 0;border-bottom:1px solid rgba(245,245,245,0.08);">
              <p style="margin:0 0 16px;font-family:Menlo,Monaco,Consolas,'Courier New',Courier,monospace;font-size:10px;font-weight:600;letter-spacing:0.22em;color:rgba(245,245,245,0.4);text-transform:uppercase;">// What each request returns</p>
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#0A0A0A;">
                <tr>
                  <td style="background:#0A0A0A;padding:6px 0;">
                    <span style="display:inline-block;width:5px;height:5px;background:#00FFC2;border-radius:50%;margin:0 14px 2px 0;vertical-align:middle;"></span>
                    <span style="font-family:-apple-system,BlinkMacSystemFont,'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:14px;color:rgba(245,245,245,0.78);line-height:1.6;">Injection detection across 22 signatures, 7 languages</span>
                  </td>
                </tr>
                <tr>
                  <td style="background:#0A0A0A;padding:6px 0;">
                    <span style="display:inline-block;width:5px;height:5px;background:#00FFC2;border-radius:50%;margin:0 14px 2px 0;vertical-align:middle;"></span>
                    <span style="font-family:-apple-system,BlinkMacSystemFont,'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:14px;color:rgba(245,245,245,0.78);line-height:1.6;">PII detection — 17 entity types (SSN, IBAN, email, passport...)</span>
                  </td>
                </tr>
                <tr>
                  <td style="background:#0A0A0A;padding:6px 0;">
                    <span style="display:inline-block;width:5px;height:5px;background:#00FFC2;border-radius:50%;margin:0 14px 2px 0;vertical-align:middle;"></span>
                    <span style="font-family:-apple-system,BlinkMacSystemFont,'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:14px;color:rgba(245,245,245,0.78);line-height:1.6;">SHA-256 signed audit report — UUID + timestamp UTC</span>
                  </td>
                </tr>
                <tr>
                  <td style="background:#0A0A0A;padding:6px 0;">
                    <span style="display:inline-block;width:5px;height:5px;background:#00FFC2;border-radius:50%;margin:0 14px 2px 0;vertical-align:middle;"></span>
                    <span style="font-family:-apple-system,BlinkMacSystemFont,'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:14px;color:rgba(245,245,245,0.78);line-height:1.6;">Mean latency: 23.4ms</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CTA -->
          <tr>
            <td align="center" style="background:#0A0A0A;padding:36px 0 32px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto;">
                <tr>
                  <td style="background:#00FFC2;border-radius:4px;">
                    <a href="https://zentricprotocol.com/quickstart"
                       style="display:inline-block;width:240px;background:#00FFC2;color:#0A0A0A;text-decoration:none;font-family:-apple-system,BlinkMacSystemFont,'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:13px;font-weight:700;letter-spacing:0.16em;text-transform:uppercase;padding:15px 16px;border-radius:4px;text-align:center;">
                      Quickstart Guide&nbsp;→
                    </a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- FOOTER -->
          <tr>
            <td style="background:#0A0A0A;padding:24px 0 0;border-top:1px solid rgba(245,245,245,0.08);">
              <p style="margin:0 0 14px;font-family:-apple-system,BlinkMacSystemFont,'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:13px;color:rgba(245,245,245,0.5);line-height:1.6;">
                Questions? Reply to this email or reach
                <a href="mailto:core@zentricprotocol.com" style="color:#00FFC2;text-decoration:none;">core@zentricprotocol.com</a>.
              </p>
              <p style="margin:0;font-family:Menlo,Monaco,Consolas,'Courier New',Courier,monospace;font-size:10px;color:rgba(245,245,245,0.35);letter-spacing:0.18em;text-transform:uppercase;">
                ZENTRIC&nbsp;PROTOCOL&nbsp;·&nbsp;zentricprotocol.com&nbsp;·&nbsp;© ZP MMXXVI
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
      `,
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Resend error: ${error}`);
  }

  return response.json();
}

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', 'https://zentricprotocol.com');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // IP rate limiting — prevents bulk account creation to abuse free tier
  const clientIP = getClientIP(req);
  const ipCheck  = checkIPRateLimit(clientIP);
  if (!ipCheck.allowed) {
    return res.status(429).json({
      error: 'RATE_LIMIT_EXCEEDED',
      message: `Too many signup attempts. Try again in ${ipCheck.resetInMinutes} minute(s).`,
    });
  }

  const { email } = req.body;

  // Validate email
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    // Check if email already registered
    const { data: existing } = await supabase
      .from('free_api_keys')
      .select('key_prefix')
      .eq('email', normalizedEmail)
      .single();

    if (existing) {
      return res.status(200).json({
        success: true,
        message: 'already_registered',
        hint: 'Check your inbox — your API key was already sent.',
      });
    }

    // Generate API key
    const rawKey = generateApiKey();
    const keyHash = hashKey(rawKey);
    const keyPrefix = rawKey.substring(0, 16); // "zp_live_a1b2c3xx"

    // Send welcome email FIRST — if Resend fails, we don't insert so the
    // user can retry. A stored-but-never-emailed key is worse than a retry.
    try {
      await sendWelcomeEmail(normalizedEmail, rawKey);
    } catch (emailError) {
      console.error('Resend error (email not sent, no DB insert):', emailError?.message || emailError);
      return res.status(500).json({
        error: 'EMAIL_FAILED',
        message: 'Could not send your API key by email. Please try again or contact core@zentricprotocol.com',
      });
    }

    // Email sent — now persist the key
    const { error: insertError } = await supabase
      .from('free_api_keys')
      .insert({
        email: normalizedEmail,
        key_hash: keyHash,
        key_prefix: keyPrefix,
        requests_this_month: 0,
        month_bucket: getMonthBucket(),
      });

    if (insertError) {
      // Edge case: email was sent but DB insert failed.
      // Log it so we can manually add the record — don't surface to user.
      console.error('DB insert failed after email sent:', insertError, 'email:', normalizedEmail, 'prefix:', keyPrefix);
    }

    return res.status(200).json({
      success: true,
      message: 'api_key_sent',
      hint: 'Check your inbox (and spam folder) for your API key.',
    });

  } catch (error) {
    console.error('Waitlist error:', error);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
}
