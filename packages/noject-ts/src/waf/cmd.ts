import { WAFVerdict } from '../types';

export const CMD_PATTERNS: Array<{ regex: RegExp; reason: string; cwe: string }> = [
  // Widened from a handful of named commands to a broad set of
  // interpreters/recon/exfil binaries — a short allowlist after ";"/"|"/
  // "&&" leaves any unlisted command (e.g. "; id") free to pass.
  { regex: /(;\s*|\|\s*|&&\s*|\$\(|`)\s*(cat\s+\/etc\/|\/bin\/(sh|bash|zsh|dash)|cmd\.exe|powershell|curl\s+http|wget\s+http|rm\s+-rf|id\b|whoami\b|uname\b|nc\b|ncat\b|netcat\b|python[23]?\b|perl\b|ruby\b|nohup\b|chmod\b|chown\b|kill\b|pkill\b)/i, reason: 'CMD: Dangerous Shell Binary', cwe: 'CWE-78' },
  { regex: /\$\(\s*\w+\s*\)/, reason: 'CMD: Subshell Execution', cwe: 'CWE-78' },
  { regex: /\|\s*(sh|bash|zsh|dash|python[23]?|perl|ruby)\b/i, reason: 'CMD: Pipe to Shell', cwe: 'CWE-78' },
  // Decode-then-execute is a classic signature-WAF-evasion primitive
  // (encode the real payload, decode it server-side, pipe to a shell).
  { regex: /base64\s+(-d|--decode)\s*\|\s*(sh|bash|zsh|python[23]?|perl|ruby)\b/i, reason: 'CMD: Encoded payload decoded and piped to an interpreter', cwe: 'CWE-78' },
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
