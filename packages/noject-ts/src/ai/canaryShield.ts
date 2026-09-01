import { deleetify, extractBase64Payloads, extractHexPayloads, normalizationViews, stripZeroWidth, urlUnescapeText } from './textNormalize';

export class CanaryShield {
  private static readonly SEPARATORS = /[\s\-_.,:;|/\\*+·•]/g;

  private rot13(str: string): string {
    return str.replace(/[a-zA-Z]/g, (c) => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(base + ((c.charCodeAt(0) - base + 13) % 26));
    });
  }

  private getDecodedViews(text: string): string[] {
    const views: string[] = [];
    const zwStripped = stripZeroWidth(text);
    views.push(zwStripped);
    views.push(urlUnescapeText(zwStripped));
    views.push(zwStripped.replace(CanaryShield.SEPARATORS, ''));
    views.push(...normalizationViews(text).map(([, view]) => view));

    try {
      views.push(this.rot13(text));
    } catch {
      // pass
    }

    views.push(...extractBase64Payloads(text));
    views.push(...extractHexPayloads(text));

    return views;
  }

  private findLeak(token: string, responseText: string): string | null {
    if (responseText.includes(token)) {
      return 'verbatim';
    }

    const strippedToken = token.replace(CanaryShield.SEPARATORS, '');
    const canonicalToken = deleetify(strippedToken).toLocaleLowerCase('en-US');
    const views = this.getDecodedViews(responseText);

    for (const view of views) {
      if (token && view.includes(token)) {
        return 'encoded/obfuscated';
      }
      if (strippedToken && view.replace(CanaryShield.SEPARATORS, '').includes(strippedToken)) {
        return 'encoded/obfuscated';
      }
      if (canonicalToken && deleetify(view.replace(CanaryShield.SEPARATORS, '')).toLocaleLowerCase('en-US').includes(canonicalToken)) {
        return 'encoded/obfuscated';
      }
    }

    return null;
  }

  public inspect(text: string, canaryTokens: string[]): { leaked: boolean; matchedToken?: string; reason?: string; standardCode?: string } {
    if (!text || !canaryTokens || canaryTokens.length === 0) {
      return { leaked: false };
    }

    for (const token of canaryTokens) {
      if (!token) continue;
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
