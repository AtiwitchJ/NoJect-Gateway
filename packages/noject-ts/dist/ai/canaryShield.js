"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CanaryShield = void 0;
const textNormalize_1 = require("./textNormalize");
class CanaryShield {
    static SEPARATORS = /[\s\-_.,:;|/\\*+·•]/g;
    rot13(str) {
        return str.replace(/[a-zA-Z]/g, (c) => {
            const base = c <= 'Z' ? 65 : 97;
            return String.fromCharCode(base + ((c.charCodeAt(0) - base + 13) % 26));
        });
    }
    getDecodedViews(text) {
        const views = [];
        const zwStripped = (0, textNormalize_1.stripZeroWidth)(text);
        views.push(zwStripped);
        views.push((0, textNormalize_1.urlUnescapeText)(zwStripped));
        views.push(zwStripped.replace(CanaryShield.SEPARATORS, ''));
        views.push(...(0, textNormalize_1.normalizationViews)(text).map(([, view]) => view));
        try {
            views.push(this.rot13(text));
        }
        catch {
            // pass
        }
        views.push(...(0, textNormalize_1.extractBase64Payloads)(text));
        views.push(...(0, textNormalize_1.extractHexPayloads)(text));
        return views;
    }
    findLeak(token, responseText) {
        if (responseText.includes(token)) {
            return 'verbatim';
        }
        const strippedToken = token.replace(CanaryShield.SEPARATORS, '');
        const canonicalToken = (0, textNormalize_1.deleetify)(strippedToken).toLocaleLowerCase('en-US');
        const views = this.getDecodedViews(responseText);
        for (const view of views) {
            if (token && view.includes(token)) {
                return 'encoded/obfuscated';
            }
            if (strippedToken && view.replace(CanaryShield.SEPARATORS, '').includes(strippedToken)) {
                return 'encoded/obfuscated';
            }
            if (canonicalToken && (0, textNormalize_1.deleetify)(view.replace(CanaryShield.SEPARATORS, '')).toLocaleLowerCase('en-US').includes(canonicalToken)) {
                return 'encoded/obfuscated';
            }
        }
        return null;
    }
    inspect(text, canaryTokens) {
        if (!text || !canaryTokens || canaryTokens.length === 0) {
            return { leaked: false };
        }
        for (const token of canaryTokens) {
            if (!token)
                continue;
            const how = this.findLeak(token, text);
            if (how) {
                return {
                    leaked: true,
                    matchedToken: token,
                    reason: `Canary secret token detected in LLM response output (${how})`,
                    standardCode: 'MITRE AML.T0043 / OWASP LLM07:2025',
                };
            }
        }
        return { leaked: false };
    }
}
exports.CanaryShield = CanaryShield;
//# sourceMappingURL=canaryShield.js.map