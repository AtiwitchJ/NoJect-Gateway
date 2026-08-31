import { WAFVerdict } from '../types';
import { inspectCMD } from './cmd';
import { inspectPathTraversal } from './pathTraversal';
import { inspectSQLi } from './sqli';
import { inspectXSS } from './xss';
import { normalizeInput } from './normalize';

export class WAFEngine {
  public inspect(input: string): WAFVerdict {
    if (!input) {
      return { blocked: false, threatType: 'NONE', confidence: 0.0 };
    }

    // Decode URL/HTML encoding and unwrap comment-obfuscation before any
    // signature check runs, so a payload can't hide behind encoding the
    // regexes below were never going to see through on their own.
    const norm = normalizeInput(input);

    // 1. Command Injection (Check chained shell commands first)
    const cmdRes = inspectCMD(norm);
    if (cmdRes) return cmdRes;

    // 2. Path Traversal
    const pathRes = inspectPathTraversal(norm);
    if (pathRes) return pathRes;

    // 3. SQL Injection
    const sqliRes = inspectSQLi(norm);
    if (sqliRes) return sqliRes;

    // 4. XSS
    const xssRes = inspectXSS(norm);
    if (xssRes) return xssRes;

    return { blocked: false, threatType: 'NONE', confidence: 0.0 };
  }
}
