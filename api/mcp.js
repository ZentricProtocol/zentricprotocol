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
        description: 'Analyze a prompt for injection attacks and PII before sending it to an LLM. Returns verdict (CLEARED/BLOCKED), matched signatures, detected PII entities, SHA-256 hash, and audit report.',
        inputSchema: {
          type: 'object',
          properties: {
            input: { type: 'string', description: 'The prompt or text to analyze.' },
            modules: { type: 'array', items: { type: 'string', enum: ['integrity', 'privacy'] }, default: ['integrity', 'privacy'] },
          },
          required: ['input'],
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
