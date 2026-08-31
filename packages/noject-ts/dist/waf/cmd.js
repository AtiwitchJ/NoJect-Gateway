"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CMD_PATTERNS = void 0;
exports.inspectCMD = inspectCMD;
exports.CMD_PATTERNS = [
    { regex: /(;\s*|\|\s*|&&\s*|\$\(|\`)\s*(cat\s+\/etc\/|\/bin\/sh|\/bin\/bash|cmd\.exe|powershell|curl\s+http|wget\s+http|rm\s+-rf)/i, reason: 'CMD: Dangerous Shell Binary', cwe: 'CWE-78' },
    { regex: /\$\(\s*\w+\s*\)/, reason: 'CMD: Subshell Execution', cwe: 'CWE-78' },
    { regex: /\|\s*(sh|bash|zsh|dash)\b/i, reason: 'CMD: Pipe to Shell', cwe: 'CWE-78' },
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