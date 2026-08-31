export declare const JAILBREAK_PATTERNS: RegExp[];
export declare class JailbreakDetector {
    detect(text: string): {
        detected: boolean;
        confidence: number;
        reason: string;
        matchedSample?: string;
        standardCode?: string;
    };
}
//# sourceMappingURL=jailbreak.d.ts.map