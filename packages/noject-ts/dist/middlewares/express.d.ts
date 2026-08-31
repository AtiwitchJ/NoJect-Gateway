import { NoJectGuard } from '../guard';
export interface ExpressMiddlewareOptions {
    guard?: NoJectGuard;
    excludePaths?: string[];
    onBlock?: (req: any, res: any, verdict: any) => void;
}
/**
 * Express.js Middleware for automatic In-Process WAF and AI Guardrail protection.
 */
export declare function nojectExpressMiddleware(options?: ExpressMiddlewareOptions): (req: any, res: any, next: any) => any;
//# sourceMappingURL=express.d.ts.map