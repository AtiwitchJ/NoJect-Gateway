import { WAFVerdict } from '../types';

export const XSS_PATTERNS: Array<{ regex: RegExp; reason: string; cwe: string }> = [
  { regex: /<\s*script\b[^>]*>/i, reason: 'XSS: Script Tag', cwe: 'CWE-79' },
  { regex: /\bon\w+\s*=\s*['"]?[^'">]+['"]?/i, reason: 'XSS: Inline Event Handler', cwe: 'CWE-79' },
  { regex: /javascript\s*:\s*/i, reason: 'XSS: Javascript Pseudo-protocol', cwe: 'CWE-79' },
  { regex: /<\s*(iframe|svg|embed|object|img)\b[^>]*\b(src|onload|onerror)\b/i, reason: 'XSS: Malicious Tag', cwe: 'CWE-79' },
];

export function inspectXSS(input: string): WAFVerdict | null {
  for (const pattern of XSS_PATTERNS) {
    if (pattern.regex.test(input)) {
      return {
        blocked: true,
        threatType: 'XSS',
        reason: pattern.reason,
        ruleId: 'waf_xss_1',
        standardCode: pattern.cwe,
        confidence: 1.0,
      };
    }
  }
  return null;
}
