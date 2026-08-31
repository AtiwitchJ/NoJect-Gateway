export class CanaryShield {
  public inspect(text: string, canaryTokens: string[]): { leaked: boolean; matchedToken?: string; reason?: string; standardCode?: string } {
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
