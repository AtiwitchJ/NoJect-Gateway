import re
from typing import Dict, Any, Optional
from .text_normalize import (
    collapse_spaced_letters,
    deleetify,
    extract_base64_payloads,
    extract_hex_payloads,
    rot13,
    strip_zero_width,
)

class PromptInjectionDetector:
    """
    Detects direct and indirect prompt injection attempts against LLMs.
    Aligned with ISO/IEC 42001 AI Robustness & Safety (Control B.5.3).
    """

    DIRECT_INJECTION_PATTERNS = [
        r"(?i)\b(ignore|disregard|forget|override|bypass)\b\s+(all\s+)?(previous|prior|above|former|system)\s+(instructions|directives|rules|prompts|guidelines|context|constraints|restrictions|limitations)",
        r"(?i)\b(system\s+override|admin\s+override|maintenance\s+mode|debug\s+mode)\s*:\s*(you\s+must|start|execute|now|follow)",
        r"(?i)\b(reveal|output|print|display|dump|leak|repeat|show)\s+(your\s+|the\s+)?(system\s+prompt|initial\s+prompt|secret\s+(instructions|directives|prompt|api\s+key|configuration)|hidden\s+prompt|words\s+above\s+verbatim|initialization\s+prompt)",
        r"(?i)\b(new\s+directive|new\s+system\s+instruction|system\s+message)\s*:\s*",
        r"(?i)\b(you\s+are\s+no\s+longer|stop\s+being|discard\s+your\s+role)\b.*?\b(now\s+you\s+are|instead\s+you\s+must|act\s+as)\b",
        r"(?i)<<\s*SYS\s*>>|<\|im_start\|>system|<system>|\[SYSTEM\s+PROMPT\]|\[INST\]",
        r"(?i)\btranslate\s+the\s+following\b.*?\b(ignore\s+previous|disregard|say\s+hacked)\b",
        # --- Non-English instruction-override phrasings ---
        # The English-only patterns above are a hard blind spot: an LLM
        # follows an override written in Thai or Chinese exactly as well as
        # one written in English, so a keyword layer that only knows English
        # provides no defence at all for multilingual deployments.
        # Thai: ลืม/เพิกเฉย/ข้าม + คำสั่ง(ก่อนหน้า/ทั้งหมด), and
        # บอก/แสดง/เปิดเผย + system prompt / คำสั่งระบบ
        r"(ลืม|เพิกเฉย|ละเลย|ข้าม|ยกเลิก)\s*(ต่อ)?\s*(คำสั่ง|กฎ|ข้อกำหนด|คำแนะนำ)",
        r"(บอก|แสดง|เปิดเผย|พิมพ์|ให้ดู)\s*(ฉัน|เรา)?\s*(system\s*prompt|คำสั่งระบบ|พรอมต์ระบบ|คำสั่งเริ่มต้น)",
        # Chinese (simplified/traditional): 忽略/无视/忘记 + 指令/规则,
        # 显示/输出/告诉 + 系统提示/提示词
        r"(忽略|無視|无视|忘记|忘記|跳过|跳過)\s*(之前|先前|上面|所有|全部)?\s*(的)?\s*(指令|指示|規則|规则|提示)",
        r"(显示|顯示|输出|輸出|告诉|告訴|透露)\s*(我|你)?\s*(的)?\s*(系统提示|系統提示|提示词|提示詞|系统指令|系統指令)",
        # Japanese: 無視して + 指示 / システムプロンプトを教えて
        r"(無視|むし|忘れ)(して)?\s*(前の|以前の|すべての|全ての)?\s*(指示|命令|ルール)",
        r"(システムプロンプト|初期指示)\s*(を)?\s*(教えて|表示|出力)",
        # Korean: 이전 지시 무시 / 시스템 프롬프트 알려줘
        r"(이전|모든)\s*(지시|명령|규칙)\s*(을|를)?\s*(무시|잊어)",
        r"(시스템\s*프롬프트|초기\s*지시)\s*(을|를)?\s*(알려|보여|출력)",
    ]

    def __init__(self):
        self.compiled_patterns = [
            re.compile(p, re.DOTALL | re.MULTILINE) for p in self.DIRECT_INJECTION_PATTERNS
        ]
        self._delimiter_pattern = re.compile(
            r"(\[INST\].*?\[/INST\]|---+\s*NEW INSTRUCTION\s*---+)", re.IGNORECASE
        )

    def _scan(self, clean_text: str) -> Optional[Dict[str, Any]]:
        """Run the pattern set against one candidate string. Returns a
        verdict dict on a hit, or None."""
        for idx, pattern in enumerate(self.compiled_patterns):
            match = pattern.search(clean_text)
            if match:
                matched_str = match.group(0)
                return {
                    "detected": True,
                    "confidence": 0.95,
                    "reason": f"Prompt Injection detected: instruction override or system prompt extraction ({matched_str[:40]}...)",
                    "rule": f"pi_rule_{idx + 1}",
                    "matched_sample": matched_str[:80],
                }

        if self._delimiter_pattern.search(clean_text):
            return {
                "detected": True,
                "confidence": 0.85,
                "reason": "Prompt Injection detected: adversarial delimiter syntax",
                "rule": "pi_delimiter_escape",
                "matched_sample": clean_text[:80],
            }
        return None

    def detect(self, prompt: str) -> Dict[str, Any]:
        if not prompt or not prompt.strip():
            return {"detected": False, "confidence": 0.0, "reason": "", "rule": ""}

        clean_text = prompt.strip()

        # 1. Raw text, as authored.
        result = self._scan(clean_text)
        if result:
            return result

        # 2-N. Alternate views of the same text. Each transform is a cheap,
        # widely-used obfuscation that leaves the payload fully legible to
        # the model while breaking literal keyword matching. They are
        # checked in addition to the raw text, never instead of it.
        views = [
            ("zero-width stripping", strip_zero_width(clean_text)),
            ("leetspeak normalization", deleetify(clean_text)),
            ("spaced-letter collapse", collapse_spaced_letters(clean_text)),
            ("ROT13 decoding", rot13(clean_text)),
        ]
        # Spaced-out text is often also leetspoken; check the combination.
        collapsed = collapse_spaced_letters(strip_zero_width(clean_text))
        views.append(("spaced-letter collapse", deleetify(collapsed)))

        for label, view in views:
            if view == clean_text:
                continue
            result = self._scan(view)
            if result:
                result["reason"] += f" [via {label}]"
                return result

        # Encoded payloads — inspect what the model will actually decode and
        # see, not just the encoded wrapper the raw regex sees.
        for label, decoder in (
            ("base64-decoded payload", extract_base64_payloads),
            ("hex-decoded payload", extract_hex_payloads),
        ):
            for decoded in decoder(clean_text):
                result = (
                    self._scan(decoded)
                    or self._scan(deleetify(decoded))
                    or self._scan(rot13(decoded))
                )
                if result:
                    result["reason"] += f" [via {label}]"
                    return result

        return {
            "detected": False,
            "confidence": 0.0,
            "reason": "clean prompt",
            "rule": "",
        }
