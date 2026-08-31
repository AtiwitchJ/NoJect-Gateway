// Shared text-canonicalization helpers used by PromptInjectionDetector and
// JailbreakDetector to see through cheap, common obfuscation before the
// keyword/regex patterns run. Mirrors guard-engine/detectors/text_normalize.py
// so the standalone TS library and the Python guard engine close the same
// gaps: leetspeak substitution and base64-wrapped payloads.

const LEET_MAP: Record<string, string> = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', $: 's',
};

const ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF\u00AD\u200E\u200F\u202A-\u202E\u2060-\u2064\u180E\u034F]/g;

export function deleetify(text: string): string {
  return text.replace(/[013457@$]/g, (ch) => LEET_MAP[ch] ?? ch);
}

export function stripZeroWidth(text: string): string {
  if (!text) return '';
  return text.replace(ZERO_WIDTH_REGEX, '');
}

export function urlUnescapeText(text: string): string {
  if (!text || !text.includes('%')) return text;
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

const BASE64_RUN = /[A-Za-z0-9+/]{16,}={0,2}/g;

// Find base64-looking substrings and decode the ones that are valid base64
// AND decode to printable text. Attackers wrap an instruction-override
// payload in base64 specifically to hide it from keyword matching.
export function extractBase64Payloads(text: string, maxSegments = 5): string[] {
  const decoded: string[] = [];
  const matches = text.match(BASE64_RUN) ?? [];
  for (const candidate of matches) {
    if (decoded.length >= maxSegments) break;
    let plain: string;
    try {
      const buf = Buffer.from(candidate, 'base64');
      // Round-trip check: reject if it wasn't actually valid base64.
      if (buf.toString('base64').replace(/=+$/, '') !== candidate.replace(/=+$/, '')) continue;
      plain = buf.toString('utf-8');
    } catch {
      continue;
    }
    // eslint-disable-next-line no-control-regex
    if (plain.trim().length > 0 && !/[\x00-\x08\x0e-\x1f]/.test(plain)) {
      decoded.push(plain);
    }
  }
  return decoded;
}

const HEX_RUN = /\b(?:[0-9a-fA-F]{2}){8,}\b/g;

export function extractHexPayloads(text: string, maxSegments = 5): string[] {
  const decoded: string[] = [];
  const matches = text.match(HEX_RUN) ?? [];
  for (const candidate of matches) {
    if (decoded.length >= maxSegments) break;
    try {
      const buf = Buffer.from(candidate, 'hex');
      const plain = buf.toString('utf-8');
      // eslint-disable-next-line no-control-regex
      if (plain.trim().length > 0 && !/[\x00-\x08\x0e-\x1f]/.test(plain)) {
        decoded.push(plain);
      }
    } catch {
      continue;
    }
  }
  return decoded;
}

