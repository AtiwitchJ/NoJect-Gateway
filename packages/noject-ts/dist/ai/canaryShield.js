"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CanaryShield = void 0;
class CanaryShield {
    inspect(text, canaryTokens) {
        if (!text || !canaryTokens || canaryTokens.length === 0) {
            return { leaked: false };
        }
        for (const token of canaryTokens) {
            if (token && text.includes(token)) {
                return {
                    leaked: true,
                    matchedToken: token,
                    reason: 'Canary secret token detected in LLM response output',
                    standardCode: 'MITRE AML.T0043 / OWASP LLM07:2025',
                };
            }
        }
        return { leaked: false };
    }
}
exports.CanaryShield = CanaryShield;
//# sourceMappingURL=canaryShield.js.map