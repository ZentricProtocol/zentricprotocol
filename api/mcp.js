// api/mcp.js — Zentric Protocol MCP over HTTP (JSON-RPC 2.0 subset)
// Compatible with Claude Desktop remote MCP and Smithery

export const config = { runtime: 'nodejs' };

const TOOL_NAME = 'analyze_prompt';
const ENDPOINT = 'https://api.zentricprotocol.com/v1/analyze';

async function analyzePrompt(input, modules, apiKey) {
  const mods = Array.isArray(modules) && modules.length > 0 ? modules : ['integrity', 'privacy'];
  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'User-Agent': 'zentric-protocol-mcp/0.1.0',
    },
    body: JSON.stringify({ input, modules: mods, options: { language: 'auto' } }),
  });
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : {}; } catch { body = { raw: text }; }
  if (!res.ok) return { ok: false, status: res.status, error: body?.error || res.statusText };
  return body;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { method, params, id } = req.body || {};

  // Accept: "Authorization: Bearer zp_live_xxx", "Authorization: zp_live_xxx", or "apikey: zp_live_xxx"
  const apiKey = (
    (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '') ||
    req.headers['apikey'] ||
    req.headers['x-api-key'] ||
    ''
  ).trim();

  function rpcOk(result) { return res.json({ jsonrpc: '2.0', result, id: id ?? null }); }
  function rpcErr(code, message) { return res.status(200).json({ jsonrpc: '2.0', error: { code, message }, id: id ?? null }); }

  if (method === 'initialize') {
    return rpcOk({
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'zentric-protocol-mcp', version: '0.1.0' },
    });
  }

  if (method === 'tools/list') {
    return rpcOk({
      tools: [{
        name: TOOL_NAME,
        description: 'Analyze a prompt for injection attacks and PII before sending it to an LLM. Returns verdict (CLEARED/BLOCKED/ANONYMIZED), matched injection signatures, detected PII entities, SHA-256 hash, and a GDPR Art.30-compliant audit report.',
        inputSchema: {
          type: 'object',
          properties: {
            input: {
              type: 'string',
              description: 'The prompt or text to analyze for injection attacks and PII. Pass any string: user input, retrieved document, tool output, file content, or sub-agent response.',
            },
            modules: {
              type: 'array',
              items: {
                type: 'string',
                enum: ['integrity', 'privacy'],
                description: '"integrity" detects prompt injection and jailbreak patterns. "privacy" detects and anonymizes PII (names, emails, phone numbers, credit cards, etc.).',
              },
              description: 'Which Zentric analysis modules to run. "integrity" checks for injection attacks. "privacy" checks for PII. Defaults to both when omitted.',
              default: ['integrity', 'privacy'],
            },
          },
          required: ['input'],
        },
        outputSchema: {
          type: 'object',
          properties: {
            verdict: {
              type: 'string',
              enum: ['CLEARED', 'ANONYMIZED', 'BLOCKED'],
              description: 'CLEARED: safe to use as-is. ANONYMIZED: PII found and replaced — use anonymized_input instead. BLOCKED: injection attack detected — do not proceed.',
            },
            report: {
              type: 'object',
              description: 'Full analysis report including matched signatures, PII entities, SHA-256 hash, and audit metadata.',
              properties: {
                integrity: {
                  type: 'object',
                  properties: {
                    injection_detected: { type: 'boolean', description: 'True if an injection or jailbreak pattern was found.' },
                    signatures_matched: { type: 'array', items: { type: 'string' }, description: 'Matched injection signature IDs (e.g. INSTRUCTION_IGNORE, ROLE_HIJACK).' },
                    confidence: { type: 'number', description: 'Confidence score between 0 and 1.' },
                  },
                },
                privacy: {
                  type: 'object',
                  properties: {
                    pii_detected: { type: 'boolean', description: 'True if any PII entities were found.' },
                    entities: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          type: { type: 'string', description: 'PII type (e.g. EMAIL, PHONE, CREDIT_CARD, NAME).' },
                          value: { type: 'string', description: 'The original PII value.' },
                          start: { type: 'number', description: 'Start character offset.' },
                          end: { type: 'number', description: 'End character offset.' },
                        },
                      },
                    },
                  },
                },
                sha256: { type: 'string', description: 'SHA-256 hash of the input for audit trail.' },
                request_id: { type: 'string', description: 'Unique UUID for this analysis request.' },
                latency_ms: { type: 'number', description: 'API response time in milliseconds.' },
              },
            },
            anonymized_input: {
              type: 'string',
              description: 'Input with all PII replaced by type placeholders. Only present when verdict is ANONYMIZED.',
            },
          },
          required: ['verdict', 'report'],
        },
        annotations: {
          readOnlyHint: true,
          idempotentHint: true,
          openWorldHint: false,
        },
      }],
    });
  }

  if (method === 'tools/call') {
    // Auth required only for tool execution
    if (!apiKey) return rpcErr(-32001, 'API key required. Get a free key at zentricprotocol.com');
    const { name, arguments: args } = params || {};
    if (name !== TOOL_NAME) return rpcErr(-32601, `Unknown tool: ${name}`);
    if (!args?.input || typeof args.input !== 'string') return rpcErr(-32602, 'input must be a non-empty string');
    try {
      const result = await analyzePrompt(args.input, args.modules, apiKey);
      return rpcOk({ content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
    } catch (err) {
      return rpcErr(-32603, `Zentric MCP error: ${err?.message || String(err)}`);
    }
  }

  return rpcErr(-32601, `Method not found: ${method}`);
}
