"""
Pure Python Lexical Fast-Path WAF (CWE-89, CWE-79, CWE-78, CWE-22)
"""

import re
from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class WAFVerdict:
    blocked: bool
    threat_type: str = ""
    reason: str = ""
    rule_id: str = ""
    standard_code: str = ""
    confidence: float = 0.0

class WAFEngine:
    # Pre-compiled Regex Vectors
    SQLI_PATTERNS = [
        (re.compile(r"(?i)\b(UNION\s+(ALL\s+)?SELECT|UNION\s+SELECT)\b"), "SQLi: Union Select", "CWE-89"),
        (re.compile(r"(?i)(['\"]\s*OR\s+['\"]?1['\"]?\s*=\s*['\"]?1|['\"]\s*OR\s+['\"][a-zA-Z0-9]+['\"]\s*=\s*['\"][a-zA-Z0-9]+|OR\s+1\s*=\s*1\s*(--|#|/\*))"), "SQLi: Boolean True", "CWE-89"),
        (re.compile(r"(?i);\s*(DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|ALTER\s+TABLE|EXEC\s*\()\b"), "SQLi: Stacked Query", "CWE-89"),
        (re.compile(r"(?i)\b(SLEEP\s*\(\s*\d+\s*\)|BENCHMARK\s*\(\s*\d+|WAITFOR\s+DELAY\s+['\"]\d+)"), "SQLi: Time-based Blind", "CWE-89"),
        (re.compile(r"(?i)['\"]\s*(--|#|/\*)"), "SQLi: Comment Auth Bypass", "CWE-89"),
    ]

    XSS_PATTERNS = [
        (re.compile(r"(?i)<\s*script\b[^>]*>"), "XSS: Script Tag", "CWE-79"),
        (re.compile(r"(?i)\bon\w+\s*=\s*['\"]?[^'\">]+['\"]?"), "XSS: Inline Event Handler", "CWE-79"),
        (re.compile(r"(?i)javascript\s*:\s*"), "XSS: Javascript Pseudo-protocol", "CWE-79"),
        (re.compile(r"(?i)<\s*(iframe|svg|embed|object|img)\b[^>]*\b(src|onload|onerror)\b"), "XSS: Malicious Tag", "CWE-79"),
    ]

    CMD_PATTERNS = [
        (re.compile(r"(?i)(;\s*|\|\s*|&&\s*|\$\(|\`)\s*(cat\s+/etc/|/bin/(sh|bash|zsh|dash)|cmd\.exe|powershell|curl\s+https?://|wget\s+https?://|rm\s+-rf|id\b|whoami\b|uname\b|nc\b|ncat\b|netcat\b|socat\b|python[23]?\b|perl\b|ruby\b|php\b|node\b|awk\b|gawk\b|sed\b|env\b|printenv\b|find\b|xargs\b|dd\b|tar\b|openssl\b|nohup\b|chmod\b|chown\b|kill\b|pkill\b|base64\s+(-d|--decode)\b)"), "CMD: Dangerous Shell Binary", "CWE-78"),
        (re.compile(r"(\$\([^)]+\)|`[^`]+`)"), "CMD: Subshell Execution", "CWE-78"),
        (re.compile(r"(?i)\|\s*(sh|bash|zsh|dash|python[23]?|perl|ruby)\b"), "CMD: Pipe to Shell", "CWE-78"),
        (re.compile(r"(?i)base64\s+(-d|--decode)\s*\|\s*(sh|bash|zsh|python[23]?|perl|ruby)\b"), "CMD: Encoded Pipe to Shell", "CWE-78"),
        (re.compile(r"\$\{?IFS\}?"), "CMD: $IFS Obfuscation", "CWE-78"),
    ]

    PATH_PATTERNS = [
        (re.compile(r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e%2f)"), "Path Traversal: Directory Climbing", "CWE-22"),
        (re.compile(r"(?i)(/etc/passwd|/etc/shadow|/windows/system32)"), "Path Traversal: Sensitive OS Path", "CWE-22"),
    ]

    def inspect(self, input_text: str) -> WAFVerdict:
        if not input_text:
            return WAFVerdict(blocked=False)

        # 1. Command Injection (Check chained shell execution first)
        for pattern, reason, cwe in self.CMD_PATTERNS:
            if pattern.search(input_text):
                return WAFVerdict(blocked=True, threat_type="COMMAND_INJECTION", reason=reason, rule_id="waf_cmd_1", standard_code=cwe, confidence=1.0)

        # 2. Path Traversal
        for pattern, reason, cwe in self.PATH_PATTERNS:
            if pattern.search(input_text):
                return WAFVerdict(blocked=True, threat_type="PATH_TRAVERSAL", reason=reason, rule_id="waf_path_1", standard_code=cwe, confidence=1.0)

        # 3. SQL Injection
        for pattern, reason, cwe in self.SQLI_PATTERNS:
            if pattern.search(input_text):
                return WAFVerdict(blocked=True, threat_type="SQL_INJECTION", reason=reason, rule_id="waf_sqli_1", standard_code=cwe, confidence=1.0)

        # 4. XSS
        for pattern, reason, cwe in self.XSS_PATTERNS:
            if pattern.search(input_text):
                return WAFVerdict(blocked=True, threat_type="XSS", reason=reason, rule_id="waf_xss_1", standard_code=cwe, confidence=1.0)

        return WAFVerdict(blocked=False)
