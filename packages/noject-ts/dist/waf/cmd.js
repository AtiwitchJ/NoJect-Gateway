"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CMD_PATTERNS = void 0;
exports.inspectCMD = inspectCMD;
exports.CMD_PATTERNS = [
    { regex: /(;\s*|\|\s*|&&\s*|\$\(|`)\s*(cat\s+\/etc\/|\/bin\/(sh|bash|zsh|dash)|cmd\.exe|powershell|curl\s+https?:\/\/|wget\s+https?:\/\/|rm\s+-rf|id\b|whoami\b|uname\b|nc\b|ncat\b|netcat\b|socat\b|python[23]?\b|perl\b|ruby\b|php\b|node\b|awk\b|gawk\b|sed\b|env\b|printenv\b|find\b|xargs\b|dd\b|tar\b|openssl\b|nohup\b|chmod\b|chown\b|kill\b|pkill\b|base64\s+(-d|--decode)\b)/i, reason: 'CMD: Dangerous Shell Binary', cwe: 'CWE-78' },
    { regex: /(\$\([^)]+\)|`[^`]+`)/, reason: 'CMD: Subshell Execution', cwe: 'CWE-78' },
    { regex: /\|\s*(sh|bash|zsh|dash|python[23]?|perl|ruby)\b/i, reason: 'CMD: Pipe to Shell', cwe: 'CWE-78' },
    { regex: /base64\s+(-d|--decode)\s*\|\s*(sh|bash|zsh|python[23]?|perl|ruby)\b/i, reason: 'CMD: Encoded payload decoded and piped to an interpreter', cwe: 'CWE-78' },
    { regex: /\$\{?IFS\}?/, reason: 'CMD: $IFS Obfuscation', cwe: 'CWE-78' },
];
function inspectCMD(input) {
    for (const pattern of exports.CMD_PATTERNS) {
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
//# sourceMappingURL=cmd.js.map