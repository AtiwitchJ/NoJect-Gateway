export declare const PROMPT_INJECTION_PATTERNS: RegExp[];
export declare class PromptInjectionDetector {
    detect(text: string): {
        detected: boolean;
        confidence: number;
        reason: string;
        matchedSample?: string;
        standardCode?: string;
    };
}
//# sourceMappingURL=promptInjection.d.ts.map