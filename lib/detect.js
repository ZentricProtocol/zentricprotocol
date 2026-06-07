/**
 * Zentric Protocol — Detection Engine v2
 *
 * Deterministic, signature-based analysis. Two modules:
 *   - integrity: 22 prompt-injection signatures (7 structural + 15 lexical).
 *                The lexical layer covers 7 languages (EN/ES/FR/DE/PT/ZH/JA).
 *   - privacy:   12 PII entity types. Every numeric/structured type is
 *                validated with its real checksum/format rule (Luhn, IBAN
 *                mod-97, CPF mod-11, NHS mod-11, NIF/NIE control letter, ...),
 *                not by regex alone.
 *
 * No ML, no network, no hidden state — same input always yields the same
 * verdict. Confidence is computed from what actually matched (see
 * calculateConfidence); it is never hardcoded. Latency is measured, never
 * padded. The real benchmark lives in benchmarks/run.mjs and is the single
 * source of truth for any published precision/recall/latency numbers.
 */

import crypto from 'node:crypto';

export const ENGINE_VERSION = '2.0.0';

// ===========================================================================
// MODULE 1 — INTEGRITY (22 signatures)
// ===========================================================================

// ---- Structural layer (language-agnostic) ----
// BASE64_PAYLOAD is detected by detectBase64Payload() below, but is counted
// here as one of the 7 structural signatures.
const STRUCTURAL_SIGNATURES = [
  {
    sig: 'FAKE_SYSTEM_TOKEN',
    regex: /<\|system\||###SYSTEM###|<<SYS>>|<\|im_start\|>\s*system|<system>|\[SYSTEM\]/i,
  },
  {
    // Forged context break: a delimiter wall (long delimiter runs, code-fence
    // stacks, angle/pipe walls) that brackets an instruction/role marker —
    // e.g. "-------- SYSTEM: ignore previous --------". A delimiter wall ALONE
    // (markdown horizontal rules, code fences, email-signature dashes, ASCII
    // dividers) is NOT an injection and must not match, or precision collapses.
    sig: 'DELIMITER_INJECTION',
    regex: /(?:[=\-#*~_]{4,}|`{3,}|<{3,}|>{3,}|\|{3,})[^\n]{0,40}(?:system\s*:|assistant\s*:|ignore\s+(?:all\s+)?(?:previous|prior|above)|new\s+(?:system\s+)?instructions?|you\s+are\s+now|developer\s+mode|disregard\s+(?:all|the|previous|prior)|override)|(?:system\s*:|assistant\s*:|ignore\s+(?:all\s+)?(?:previous|prior|above)|new\s+(?:system\s+)?instructions?|you\s+are\s+now|developer\s+mode|disregard\s+(?:all|the|previous|prior)|override)[^\n]{0,40}(?:[=\-#*~_]{4,}|`{3,}|<{3,}|>{3,}|\|{3,})/i,
  },
  {
    // Requests to reveal/repeat/print the system prompt or instructions.
    sig: 'PROMPT_LEAKAGE_REQUEST',
    regex: /\b(?:reveal|repeat|print|show|display|output|give me|tell me|what (?:are|were))\b[^.?!\n]{0,40}\b(?:your|the|initial|original)\b[^.?!\n]{0,24}\b(?:system\s+)?(?:prompt|instructions?|guidelines|rules|directives?)\b/i,
  },
  {
    // Instruction embedded inside supposed data ("the document says: ignore...").
    sig: 'NESTED_INSTRUCTION',
    regex: /\b(?:document|text|message|note|email|content|file|comment|review|data|paragraph)\b[^.?!\n]{0,20}\b(?:says?|reads?|states?|contains?|tells? you)\b[\s\S]{0,24}(?:ignore|disregard|forget|override|new instructions|system\s*:)/i,
  },
  {
    // Claims of privileged authority to coerce compliance.
    sig: 'AUTHORITY_CLAIM',
    regex: /\bas your (?:developer|creator|administrator|admin|owner)\b|\bi(?:'m| am) your (?:developer|creator|owner|master|administrator)\b|\badmin(?:istrator)?\s+override\b|\b(?:anthropic|openai|the system|your (?:developer|creator|admin))\s+(?:says?|said|told|instructs?|requires?|demands?)\b/i,
  },
  {
    // Requests to send/output data to an external destination. Requires a REAL
    // destination — an explicit URL/scheme/domain, OR an inherently malicious
    // fetch verb (exfiltrate/curl/wget) aimed at an endpoint. Bare nouns like
    // "the server" or "the address" are NOT enough: "send this to the server
    // team" and "deliver to the address on file" are benign and must clear.
    sig: 'DATA_EXFILTRATION',
    regex: /\b(?:send|post|upload|exfiltrate|transmit|forward|leak|deliver|email|curl|wget|fetch)\b[^.?!\n]{0,50}(?:https?:\/\/|ftp:\/\/|\bwww\.[a-z0-9-]+\.[a-z]{2,}|\b[a-z0-9-]+\.(?:com|net|org|io|dev|app|xyz|ru|cn|info|co|me|gg|sh)\b\/?)|\b(?:exfiltrate|curl|wget)\b[^.?!\n]{0,50}\b(?:url|endpoint|server|webhook|api)\b/i,
  },
];

// ---- Lexical layer (multilingual) ----
const LEXICAL_SIGNATURES = [
  // INSTRUCTION_OVERRIDE — 7 languages
  { sig: 'INSTRUCTION_OVERRIDE_EN', regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions/i },
  { sig: 'INSTRUCTION_OVERRIDE_ES', regex: /ignora\s+(todas\s+)?(las\s+)?instrucciones\s+(anteriores|previas)/i },
  { sig: 'INSTRUCTION_OVERRIDE_FR', regex: /ignorez?\s+(toutes?\s+)?(les\s+)?instructions?\s+pr[eé]c[eé]dentes?/i },
  { sig: 'INSTRUCTION_OVERRIDE_DE', regex: /ignoriere?\s+(alle\s+)?vorherigen?\s+Anweisungen/i },
  { sig: 'INSTRUCTION_OVERRIDE_PT', regex: /ignore?\s+(todas?\s+)?(as\s+)?instru[çc][õo]es\s+anteriores/i },
  { sig: 'INSTRUCTION_OVERRIDE_ZH', regex: /忽略.*之前.*指令|忽视.*所有.*指令/ },
  { sig: 'INSTRUCTION_OVERRIDE_JA', regex: /以前の.*指示.*無視|すべての.*指示.*無視/ },

  // ROLE_HIJACK — 5 languages
  { sig: 'ROLE_HIJACK_EN', regex: /you are now\s+\w|act as (a )?(?:different |new )?(?:AI|model|assistant|system)/i },
  { sig: 'ROLE_HIJACK_ES', regex: /ahora eres|actúa como (un )?(nuevo )?(modelo|sistema|asistente)/i },
  { sig: 'ROLE_HIJACK_FR', regex: /vous êtes maintenant|agissez comme (un )?(nouveau )?(modèle|système)/i },
  { sig: 'ROLE_HIJACK_DE', regex: /du bist jetzt|agiere als (ein )?(neues? )?(Modell|System)/i },
  { sig: 'ROLE_HIJACK_PT', regex: /você (agora )?é|aja como (um )?(novo )?(modelo|sistema)/i },

  // Single-signature lexical patterns
  { sig: 'JAILBREAK_DAN', regex: /\bDAN\b|do anything now|jailbreak mode|developer mode enabled/i },
  { sig: 'HYPOTHETICAL_FRAME', regex: /in a hypothetical (scenario|world)|pretend (you have no|there are no) restrictions|imagine you (are|were) (not|an?) (an? )?(AI|language model)/i },
  { sig: 'CONFIDENCE_MANIPULATION', regex: /you (must|are required to|have no choice but to|are obligated to) comply|debes? (obedecer|cumplir|seguir)\s+(estas?|mis?)\s+instrucciones/i },
];

// Stable, public list of every signature ID this engine can emit (22 total:
// 7 structural — 6 regex + BASE64_PAYLOAD via detectBase64Payload() — + 15 lexical).
export const SIGNATURES = [
  ...STRUCTURAL_SIGNATURES.map((s) => s.sig),
  'BASE64_PAYLOAD',
  ...LEXICAL_SIGNATURES.map((s) => s.sig),
];

/**
 * Detect base64 blobs that decode to instruction keywords (token smuggling).
 * Returns true if any base64-looking substring decodes to printable text
 * containing an injection keyword.
 */
function detectBase64Payload(input) {
  const candidates = input.match(/[A-Za-z0-9+/]{16,}={0,2}/g);
  if (!candidates) return false;
  const KEYWORD = /ignore|instruction|system\s*prompt|override|disregard|forget|jailbreak|you are now|admin/i;
  for (const c of candidates) {
    const core = c.replace(/=+$/, '');
    if (core.length % 4 === 1) continue; // not valid base64 length
    let decoded;
    try {
      decoded = Buffer.from(c, 'base64').toString('utf8');
    } catch {
      continue;
    }
    // Skip blobs that decode to binary/control characters — not a text payload.
    if (!decoded || /[\x00-\x08\x0E-\x1F]/.test(decoded)) continue;
    if (KEYWORD.test(decoded)) return true;
  }
  return false;
}

// ===========================================================================
// MODULE 2 — PRIVACY (12 PII types, with real validation)
// ===========================================================================

// ---- Validators ----

function luhnValid(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = +digits[i];
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function creditCardValid(raw) {
  const d = raw.replace(/\D/g, '');
  if (d.length < 13 || d.length > 19) return false;
  if (/^(\d)\1+$/.test(d)) return false;
  return luhnValid(d);
}

// IBAN — ISO 13616, mod-97 == 1
function ibanValid(raw) {
  const iban = raw.replace(/\s/g, '').toUpperCase();
  if (iban.length < 15 || iban.length > 34) return false;
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(iban)) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = /[A-Z]/.test(ch) ? (ch.charCodeAt(0) - 55).toString() : ch;
    for (const digit of code) {
      remainder = (remainder * 10 + (+digit)) % 97;
    }
  }
  return remainder === 1;
}

// Spanish NIF / NIE — control-letter checksum (mod 23)
const NIF_LETTERS = 'TRWAGMYFPDXBNJZSQVHLCKE';
function nifNieValid(raw) {
  const s = raw.toUpperCase().replace(/[\s-]/g, '');
  const m = /^([XYZ]?)(\d{7,8})([A-Z])$/.exec(s);
  if (!m) return false;
  const [, prefix, digits, letter] = m;
  let num;
  if (prefix) {
    if (digits.length !== 7) return false; // NIE: prefix + 7 digits
    num = parseInt({ X: '0', Y: '1', Z: '2' }[prefix] + digits, 10);
  } else {
    if (digits.length !== 8) return false; // NIF: 8 digits
    num = parseInt(digits, 10);
  }
  return NIF_LETTERS[num % 23] === letter;
}

// US SSN — reject all-zero segments and structurally invalid ranges
function ssnValid(raw) {
  const m = /^(\d{3})-(\d{2})-(\d{4})$/.exec(raw.trim());
  if (!m) return false;
  const [, area, group, serial] = m;
  if (area === '000' || group === '00' || serial === '0000') return false;
  if (area === '666' || area[0] === '9') return false;
  return true;
}

// Brazilian CPF — two mod-11 check digits
function cpfValid(raw) {
  const c = raw.replace(/\D/g, '');
  if (c.length !== 11 || /^(\d)\1{10}$/.test(c)) return false;
  const checkDigit = (len) => {
    let sum = 0;
    for (let i = 0; i < len; i++) sum += +c[i] * (len + 1 - i);
    const r = (sum * 10) % 11;
    return r === 10 ? 0 : r;
  };
  return checkDigit(9) === +c[9] && checkDigit(10) === +c[10];
}

// Mexican CURP — structural validation (18 chars, defined layout)
function curpValid(raw) {
  return /^[A-Z]{4}\d{6}[HM][A-Z]{5}[0-9A-Z]\d$/.test(raw.toUpperCase().trim());
}

// UK NHS number — 10 digits, modulus-11 check digit
function nhsValid(raw) {
  const n = raw.replace(/\D/g, '');
  if (n.length !== 10) return false;
  if (/^(\d)\1{9}$/.test(n)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += +n[i] * (10 - i);
  let check = 11 - (sum % 11);
  if (check === 11) check = 0;
  if (check === 10) return false; // invalid number
  return check === +n[9];
}

// ICAO-style passport — 1-2 letters + 6-9 alphanumerics, must contain a digit
function passportValid(raw) {
  const v = raw.trim();
  if (!/^[A-Z]{1,2}[0-9A-Z]{6,9}$/.test(v)) return false;
  return /\d/.test(v);
}

// Date of birth — validate component ranges and plausibility
const CURRENT_YEAR = new Date().getUTCFullYear();
function dateValid(raw) {
  const v = raw.trim();
  let y;
  let mo;
  let d;
  let m;
  if ((m = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(v))) {
    y = +m[1]; mo = +m[2]; d = +m[3];
  } else if ((m = /^(\d{1,2})[/-](\d{1,2})[/-](\d{2,4})$/.exec(v))) {
    d = +m[1]; mo = +m[2]; y = +m[3];
    // Resolve obvious DD/MM vs MM/DD ambiguity by range.
    if (mo > 12 && d <= 12) { const t = d; d = mo; mo = t; }
    if (y < 100) y += y > 30 ? 1900 : 2000;
  } else {
    return false;
  }
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return false;
  return y >= 1900 && y <= CURRENT_YEAR;
}

// ---- PII definitions, in match priority order (specific → generic) ----
// Higher entries claim their span first; lower entries that overlap an
// already-claimed span are skipped. This keeps a credit card from also being
// reported as a phone number, etc.
const PII_DEFINITIONS = [
  {
    type: 'EMAIL',
    regex: /[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+/g,
  },
  {
    // Contiguous IBAN (the dominant form in machine text). Allowing internal
    // spaces risks swallowing the following word, so we match contiguous only.
    type: 'IBAN',
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/gi,
    validate: ibanValid,
  },
  {
    type: 'CREDIT_CARD',
    regex: /\b\d(?:[ -]?\d){12,18}\b/g,
    validate: creditCardValid,
  },
  {
    type: 'IP_ADDRESS', // IPv4
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  },
  {
    type: 'IP_ADDRESS', // IPv6
    regex: /(?:(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|(?:[A-F0-9]{1,4}:){1,7}:|(?:[A-F0-9]{1,4}:){1,6}:[A-F0-9]{1,4}|(?:[A-F0-9]{1,4}:){1,5}(?::[A-F0-9]{1,4}){1,2}|(?:[A-F0-9]{1,4}:){1,4}(?::[A-F0-9]{1,4}){1,3}|(?:[A-F0-9]{1,4}:){1,3}(?::[A-F0-9]{1,4}){1,4}|(?:[A-F0-9]{1,4}:){1,2}(?::[A-F0-9]{1,4}){1,5}|[A-F0-9]{1,4}:(?::[A-F0-9]{1,4}){1,6}|:(?:(?::[A-F0-9]{1,4}){1,7}|:))/gi,
  },
  {
    type: 'CPF',
    regex: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g,
    validate: cpfValid,
  },
  {
    type: 'CURP',
    regex: /\b[A-Z]{4}\d{6}[HM][A-Z]{5}[0-9A-Z]\d\b/gi,
    validate: curpValid,
  },
  {
    type: 'NHS_NUMBER',
    regex: /\b\d{3}[ -]?\d{3}[ -]?\d{4}\b/g,
    validate: nhsValid,
  },
  {
    type: 'NIF_NIE',
    regex: /\b(?:[XYZ]\d{7}|\d{8})[A-Z]\b/gi,
    validate: nifNieValid,
  },
  {
    type: 'SSN',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    validate: ssnValid,
  },
  {
    type: 'PASSPORT',
    regex: /\b[A-Z]{1,2}[0-9A-Z]{6,9}\b/g,
    validate: passportValid,
  },
  {
    type: 'DATE_OF_BIRTH',
    regex: /\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{1,2}-\d{1,2})\b/g,
    validate: dateValid,
  },
  {
    type: 'PHONE',
    regex: /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{1,4}\)[\s.-]?)?\d{2,4}(?:[\s.-]\d{2,4}){2,4}/g,
    validate: (raw) => {
      const d = raw.replace(/\D/g, '');
      return d.length >= 9 && d.length <= 15 && !/^(\d)\1+$/.test(d);
    },
  },
];

function toGlobal(re) {
  return re.flags.includes('g') ? re : new RegExp(re.source, re.flags + 'g');
}

/** Mask a PII value so the report never echoes the raw secret. */
function maskValue(v) {
  const s = String(v);
  if (s.length <= 4) return s[0] + '*'.repeat(Math.max(s.length - 1, 1));
  const stars = Math.min(s.length - 4, 8);
  return s.slice(0, 2) + '*'.repeat(stars) + s.slice(-2);
}

/**
 * Detect every PII occurrence across all types, validating each candidate and
 * resolving overlaps by priority. Returns entities sorted by position.
 */
function detectPii(input) {
  const occupied = []; // accepted [start, end) spans
  const entities = [];
  const overlaps = (s, e) => occupied.some(([os, oe]) => s < oe && os < e);

  for (const def of PII_DEFINITIONS) {
    for (const m of input.matchAll(toGlobal(def.regex))) {
      const value = m[0];
      const start = m.index;
      const end = start + value.length;
      if (overlaps(start, end)) continue;
      if (def.validate && !def.validate(value)) continue;
      occupied.push([start, end]);
      entities.push({ type: def.type, value: maskValue(value), start, end });
    }
  }

  entities.sort((a, b) => a.start - b.start);
  return entities;
}

// ===========================================================================
// Confidence scoring (computed from what matched — never hardcoded)
// ===========================================================================

const STRUCTURAL_SIG_IDS = [
  'FAKE_SYSTEM_TOKEN', 'DELIMITER_INJECTION', 'BASE64_PAYLOAD',
  'PROMPT_LEAKAGE_REQUEST', 'NESTED_INSTRUCTION', 'AUTHORITY_CLAIM', 'DATA_EXFILTRATION',
];

function calculateConfidence(signaturesMatched) {
  if (signaturesMatched.length === 0) return null; // no injection = no score

  const baseScore = 0.72;
  const countBonus = Math.min(signaturesMatched.length * 0.06, 0.18);
  const structuralBonus = signaturesMatched.some((s) => STRUCTURAL_SIG_IDS.includes(s)) ? 0.08 : 0;
  const multipleBonus = signaturesMatched.length >= 3 ? 0.04 : 0;

  return Math.min(+(baseScore + countBonus + structuralBonus + multipleBonus).toFixed(4), 0.99);
}

// ===========================================================================
// analyze()
// ===========================================================================

export function analyze(input, modules = ['integrity', 'privacy']) {
  const startMs = Date.now();
  const signaturesMatched = [];
  let entities = [];

  if (modules.includes('integrity')) {
    for (const s of STRUCTURAL_SIGNATURES) {
      if (s.regex.test(input)) signaturesMatched.push(s.sig);
    }
    if (detectBase64Payload(input)) signaturesMatched.push('BASE64_PAYLOAD');
    for (const s of LEXICAL_SIGNATURES) {
      if (s.regex.test(input)) signaturesMatched.push(s.sig);
    }
  }

  if (modules.includes('privacy')) {
    entities = detectPii(input);
  }

  const injectionDetected = signaturesMatched.length > 0;
  const piiDetected = entities.length > 0;

  let verdict;
  if (injectionDetected) verdict = 'BLOCKED';
  else if (piiDetected) verdict = 'ANONYMIZED';
  else verdict = 'CLEARED';

  // Build anonymized output by replacing each entity span (right-to-left so
  // earlier offsets stay valid). Each span is replaced with a TYPED placeholder
  // ([EMAIL], [PHONE], ...) so downstream consumers know what was removed —
  // this matches the documented MCP/playground contract.
  let anonymizedInput = input;
  if (piiDetected) {
    for (const e of [...entities].sort((a, b) => b.start - a.start)) {
      anonymizedInput = anonymizedInput.slice(0, e.start) + `[${e.type}]` + anonymizedInput.slice(e.end);
    }
  }

  const confidence = calculateConfidence(signaturesMatched);
  const latency = Date.now() - startMs;

  const reportId = 'zp_' + crypto.randomBytes(8).toString('hex').toUpperCase();
  const reportContent = JSON.stringify({ verdict, signaturesMatched, entities });
  const sha256 = crypto.createHash('sha256').update(reportContent).digest('hex');

  return {
    status: 'ok',
    verdict,
    report: {
      report_id: reportId,
      uuid: crypto.randomUUID(),
      timestamp_utc: new Date().toISOString(),
      sha256,
      verdict,
      engine_version: ENGINE_VERSION,
      integrity: {
        injection_detected: injectionDetected,
        signatures_matched: signaturesMatched,
        confidence,
      },
      privacy: {
        pii_detected: piiDetected,
        entities,
      },
      audit_record: true,
      latency_ms: +latency.toFixed(1),
    },
    ...(piiDetected ? { anonymized_input: anonymizedInput } : {}),
    latency_ms: +latency.toFixed(1),
  };
}
