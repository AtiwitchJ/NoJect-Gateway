"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WAFEngine = void 0;
const cmd_1 = require("./cmd");
const pathTraversal_1 = require("./pathTraversal");
const sqli_1 = require("./sqli");
const xss_1 = require("./xss");
class WAFEngine {
    inspect(input) {
        if (!input) {
            return { blocked: false, threatType: 'NONE', confidence: 0.0 };
        }
        // 1. Command Injection (Check chained shell commands first)
        const cmdRes = (0, cmd_1.inspectCMD)(input);
        if (cmdRes)
            return cmdRes;
        // 2. Path Traversal
        const pathRes = (0, pathTraversal_1.inspectPathTraversal)(input);
        if (pathRes)
            return pathRes;
        // 3. SQL Injection
        const sqliRes = (0, sqli_1.inspectSQLi)(input);
        if (sqliRes)
            return sqliRes;
        // 4. XSS
        const xssRes = (0, xss_1.inspectXSS)(input);
        if (xssRes)
            return xssRes;
        return { blocked: false, threatType: 'NONE', confidence: 0.0 };
    }
}
exports.WAFEngine = WAFEngine;
//# sourceMappingURL=index.js.map