"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.nojectExpressMiddleware = nojectExpressMiddleware;
const guard_1 = require("../guard");
/**
 * Express.js Middleware for automatic In-Process WAF and AI Guardrail protection.
 */
function nojectExpressMiddleware(options) {
    const guard = options?.guard ?? new guard_1.NoJectGuard();
    const excludePaths = options?.excludePaths ?? ['/health', '/metrics'];
    return (req, res, next) => {
        if (excludePaths.includes(req.path)) {
            return next();
        }
        // 1. Inspect Query Parameters with WAF
        if (req.query && Object.keys(req.query).length > 0) {
            const queryString = new URLSearchParams(req.query).toString();
            const verdict = guard.inspectRequest(queryString);
            if (verdict.blocked) {
                if (options?.onBlock) {
                    return options.onBlock(req, res, verdict);
                }
                return res.status(403).json({
                    error: 'Forbidden by NoJect Security Guard',
                    threatCategory: verdict.threatType,
                    reason: verdict.reason,
                    standardCode: verdict.standardCode,
                });
            }
        }
        // 2. Inspect Body for AI Prompts / JSON attacks
        if (req.body) {
            const bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
            const verdict = guard.inspectPrompt(bodyStr);
            if (verdict.isBlocked) {
                if (options?.onBlock) {
                    return options.onBlock(req, res, verdict);
                }
                return res.status(403).json({
                    error: 'Blocked by NoJect AI Security Shield',
                    threatCategory: verdict.threatCategory,
                    reason: verdict.reason,
                    standardCode: verdict.standardCode,
                });
            }
        }
        next();
    };
}
//# sourceMappingURL=express.js.map