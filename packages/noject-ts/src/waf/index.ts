import { WAFVerdict } from '../types';
import { inspectCMD } from './cmd';
import { inspectPathTraversal } from './pathTraversal';
import { inspectSQLi } from './sqli';
import { inspectXSS } from './xss';

export class WAFEngine {
  public inspect(input: string): WAFVerdict {
    if (!input) {
      return { blocked: false, threatType: 'NONE', confidence: 0.0 };
    }

    // 1. Command Injection (Check chained shell commands first)
    const cmdRes = inspectCMD(input);
    if (cmdRes) return cmdRes;

    // 2. Path Traversal
    const pathRes = inspectPathTraversal(input);
    if (pathRes) return pathRes;

    // 3. SQL Injection
    const sqliRes = inspectSQLi(input);
    if (sqliRes) return sqliRes;

    // 4. XSS
    const xssRes = inspectXSS(input);
    if (xssRes) return xssRes;

    return { blocked: false, threatType: 'NONE', confidence: 0.0 };
  }
}
