export declare class CanaryShield {
    private static readonly SEPARATORS;
    private rot13;
    private getDecodedViews;
    private findLeak;
    inspect(text: string, canaryTokens: string[]): {
        leaked: boolean;
        matchedToken?: string;
        reason?: string;
        standardCode?: string;
    };
}
//# sourceMappingURL=canaryShield.d.ts.map