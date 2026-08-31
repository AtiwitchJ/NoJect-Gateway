import { WAFVerdict } from '../types';

export const PATH_PATTERNS: Array<{ regex: RegExp; reason: string; cwe: string }> = [
  { regex: /(\.\.\/|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e%2f)/, reason: 'Path Traversal: Directory Climbing', cwe: 'CWE-22' },
  { regex: /(\/etc\/passwd|\/etc\/shadow|\/windows\/system32)/i, reason: 'Path Traversal: Sensitive OS Path', cwe: 'CWE-22' },
];

export function inspectPathTraversal(input: string): WAFVerdict | null {
  for (const pattern of PATH_PATTERNS) {
    if (pattern.regex.test(input)) {
      return {
        blocked: true,
        threatType: 'PATH_TRAVERSAL',
        reason: pattern.reason,
        ruleId: 'waf_path_1',
        standardCode: pattern.cwe,
        confidence: 1.0,
      };
    }
  }
  return null;
}
