/**
 * NoJect TypeScript Definitions
 */
export interface GuardVerdict {
    isBlocked: boolean;
    threatCategory: string;
    reason?: string;
    standardCode?: string;
    confidence: number;
    matchedSample?: string;
    maskedText?: string;
    hasPii?: boolean;
    entitiesFound?: string[];
}
export interface WAFVerdict {
    blocked: boolean;
    threatType: string;
    reason?: string;
    ruleId?: string;
    standardCode?: string;
    confidence: number;
}
export interface GuardOptions {
    enableWAF?: boolean;
    enableAIGuard?: boolean;
    enablePIIMasking?: boolean;
}
//# sourceMappingURL=types.d.ts.map