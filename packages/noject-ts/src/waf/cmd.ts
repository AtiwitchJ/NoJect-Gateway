import { WAFVerdict } from '../types';

export const CMD_PATTERNS: Array<{ regex: RegExp; reason: string; cwe: string }> = [
  { regex: /(;\s*|\|\s*|&&\s*|\$\(|\`)\s*(cat\s+\/etc\/|\/bin\/sh|\/bin\/bash|cmd\.exe|powershell|curl\s+http|wget\s+http|rm\s+-rf)/i, reason: 'CMD: Dangerous Shell Binary', cwe: 'CWE-78' },
  { regex: /\$\(\s*\w+\s*\)/, reason: 'CMD: Subshell Execution', cwe: 'CWE-78' },
  { regex: /\|\s*(sh|bash|zsh|dash)\b/i, reason: 'CMD: Pipe to Shell', cwe: 'CWE-78' },
];

export function inspectCMD(input: string): WAFVerdict | null {
  for (const pattern of CMD_PATTERNS) {
    if (pattern.regex.test(input)) {
      return {
        blocked: true,
        threatType: 'COMMAND_INJECTION',
        reason: pattern.reason,
        ruleId: 'waf_cmd_1',
        standardCode: pattern.cwe,
        confidence: 1.0,
      };
    }
  }
  return null;
}
