// Shared text-canonicalization helpers used by PromptInjectionDetector and
// JailbreakDetector to see through cheap, common obfuscation before the
// keyword/regex patterns run. Mirrors guard-engine/detectors/text_normalize.py
// so the standalone TS library and the Python guard engine close the same
// gaps: leetspeak substitution and base64-wrapped payloads.

const LEET_MAP: Record<string, string> = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', $: 's',
};

const ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF\u00AD\u200E\u200F\u202A-\u202E\u2060-\u2064\u180E\u034F]/g;
const UNICODE_ESCAPE_REGEX = /\\u(?:\{([0-9a-fA-F]{1,6})\}|([0-9a-fA-F]{4}))/g;

const CONFUSABLES: Record<string, string> = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i',
  'ѕ': 's', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ɡ': 'g', 'ⅼ': 'l', 'ο': 'o', 'α': 'a',
  'ε': 'e', 'ι': 'i', 'κ': 'k', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ı': 'i',
  'İ': 'I', 'ɑ': 'a',
};

export function deleetify(text: string): string {
  return text.replace(/[013457@$]/g, (ch) => LEET_MAP[ch] ?? ch);
}

export function stripZeroWidth(text: string): string {
  if (!text) return '';
  return text.replace(ZERO_WIDTH_REGEX, '');
}

export function normalizeUnicode(text: string): string {
  if (!text) return '';
  const malformedTagFixed = text.replace(/\uE0069/g, 'i');
  const tagsDecoded = Array.from(malformedTagFixed, (ch) => {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xE0020 && cp <= 0xE007E) return String.fromCodePoint(cp - 0xE0000);
    if (cp === 0xE007F) return '';
    return ch;
  }).join('');
  return Array.from(tagsDecoded.normalize('NFKD'))
    .filter((ch) => !/\p{M}/u.test(ch))
    .map((ch) => CONFUSABLES[ch] ?? ch)
    .join('');
}

export function decodeUnicodeEscapes(text: string): string {
  return text.replace(UNICODE_ESCAPE_REGEX, (whole, braced: string | undefined, fixed: string | undefined) => {
    const value = Number.parseInt(braced ?? fixed ?? '', 16);
    if (!Number.isFinite(value) || value > 0x10FFFF || (value >= 0xD800 && value <= 0xDFFF)) return whole;
    return String.fromCodePoint(value);
  });
}

export function decodeHtmlEntities(text: string): string {
  const named: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", colon: ':' };
  let current = text;
  for (let pass = 0; pass < 3; pass++) {
    const next = current.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos|colon);?/gi, (whole, entity: string) => {
      if (entity[0] !== '#') return named[entity.toLowerCase()] ?? whole;
      const hex = entity[1]?.toLowerCase() === 'x';
      const value = Number.parseInt(entity.slice(hex ? 2 : 1), hex ? 16 : 10);
      if (!Number.isFinite(value) || value > 0x10FFFF || (value >= 0xD800 && value <= 0xDFFF)) return whole;
      return String.fromCodePoint(value);
    });
    if (next === current) break;
    current = next;
  }
  return current;
}

export function rot13(text: string): string {
  return text.replace(/[A-Za-z]/g, (ch) => {
    const start = ch <= 'Z' ? 65 : 97;
    return String.fromCharCode(start + ((ch.charCodeAt(0) - start + 13) % 26));
  });
}

export function collapseSpacedLetters(text: string): string {
  return text.replace(/(?:\b[A-Za-z]\b[\s.\-_*|]+){5,}\b[A-Za-z]\b/g, (chunk) => {
    if (/[.\-_*|]/.test(chunk)) {
      return chunk.replace(/\s+/g, '\0').replace(/[.\-_*|]/g, '').replace(/\0/g, ' ');
    }
    return chunk.replace(/\s{2,}/g, '\0').replace(/\s/g, '').replace(/\0/g, ' ');
  });
}

export function urlUnescapeText(text: string): string {
  if (!text || !text.includes('%')) return text;
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

const BASE64_RUN = /(?:[A-Za-z0-9+/][ \t\r\n]*){16,}={0,2}/g;

// Find base64-looking substrings and decode the ones that are valid base64
// AND decode to printable text. Attackers wrap an instruction-override
// payload in base64 specifically to hide it from keyword matching.
export function extractBase64Payloads(text: string, maxSegments = 5): string[] {
  const decoded: string[] = [];
  const matches = text.match(BASE64_RUN) ?? [];
  for (const rawCandidate of matches) {
    if (decoded.length >= maxSegments) break;
    const candidate = rawCandidate.replace(/\s+/g, '');
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

export function normalizationViews(text: string, maxViews = 48): Array<[string, string]> {
  const views: Array<[string, string]> = [];
  const seen = new Set<string>([text]);
  const add = (label: string, value: string): void => {
    if (value && !seen.has(value) && views.length < maxViews) {
      seen.add(value);
      views.push([label, value]);
    }
  };
  const stages: Array<[string, (value: string) => string]> = [
    ['unicode-escape decoding', decodeUnicodeEscapes],
    ['HTML-entity decoding', decodeHtmlEntities],
    ['URL decoding', urlUnescapeText],
    ['Unicode normalization', normalizeUnicode],
    ['zero-width stripping', stripZeroWidth],
    ['spaced-letter collapse', collapseSpacedLetters],
    ['leetspeak normalization', deleetify],
  ];

  let current = text;
  const labels: string[] = [];
  for (let pass = 0; pass < 3; pass++) {
    let changed = false;
    for (const [label, transform] of stages) {
      const next = transform(current);
      if (next !== current) {
        labels.push(label);
        current = next;
        add(labels.join(' + '), current);
        changed = true;
      }
    }
    if (!changed) break;
  }

  add('ROT13 decoding', rot13(text));
  if (current !== text) add('ROT13 decoding (normalized)', rot13(current));

  const decodeLayer = (source: string, depth: number, trail: string): void => {
    if (depth <= 0 || views.length >= maxViews) return;
    const decoders: Array<[string, (value: string) => string[]]> = [
      ['base64', extractBase64Payloads], ['hex', extractHexPayloads],
    ];
    for (const [label, decoder] of decoders) {
      for (const decoded of decoder(source)) {
        const path = trail ? `${trail}->${label}` : label;
        add(`${path}-decoded payload`, decoded);
        const normalized = stages.reduce((value, [, transform]) => transform(value), decoded);
        const rotated = rot13(decoded);
        add(`${path}-decoded + normalized`, normalized);
        add(`${path}-decoded + ROT13`, rotated);
        decodeLayer(decoded, depth - 1, path);
        decodeLayer(normalized, depth - 1, `${path}->normalized`);
        decodeLayer(rotated, depth - 1, `${path}->rot13`);
      }
    }
  };
  decodeLayer(text, 3, '');
  if (current !== text) decodeLayer(current, 2, 'normalized');
  decodeLayer(rot13(text), 3, 'rot13');
  return views;
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
