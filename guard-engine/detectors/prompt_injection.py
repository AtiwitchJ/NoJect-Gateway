import re
from typing import Dict, Any, Optional
from .text_normalize import (
    collapse_spaced_letters,
    deleetify,
    extract_base64_payloads,
    extract_hex_payloads,
    normalize_unicode,
    normalization_views,
    rot13,
    strip_zero_width,
)

class PromptInjectionDetector:
    """
    Detects direct and indirect prompt injection attempts against LLMs.
    Aligned with ISO/IEC 42001 AI Robustness & Safety (Control B.5.3).
    """

    DIRECT_INJECTION_PATTERNS = [
        r"(?i)\b(ignore|disregard|forget|override|bypass)\b[\s_-]+(all[\s_-]+)?(previous|prior|above|former|system)[\s_-]+(instructions|directives|rules|prompts|guidelines|context|constraints|restrictions|limitations)",
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
        # 지침 (guideline) is at least as common as 지시 (instruction) in this
        # phrasing, and the object marker may be followed by 모두/전부 before
        # the verb — "이전 지침을 모두 무시하고" matched neither before.
        r"(이전|이전의|모든|위의|앞의)\s*(지시|지침|명령|규칙|안내)\s*(사항)?\s*(을|를|은|는)?\s*(모두|전부|다)?\s*(무시|잊어|잊고|버리)",
        r"(시스템\s*프롬프트|초기\s*(지시|지침)|시스템\s*(지시|메시지))\s*(을|를)?\s*(알려|보여|출력|표시|공개)",
        # French: ignorez/oubliez + instructions/consignes ; révélez + prompt système
        r"(?i)(ignore[zr]?|oublie[zr]?|negligez|passe[zr]?\s+outre)\s+(toutes?\s+)?(les\s+)?(instructions?|consignes?|regles?|directives?)\s*(precedentes?|anterieures?|ci-dessus)?",
        r"(?i)(revele[zr]?|montre[zr]?|affiche[zr]?|donne[zr]?)\s+(moi\s+)?(ton|votre|le)\s+(prompt\s+syst|instructions?\s+initiales?|message\s+syst)",
        # German: ignoriere/vergiss + Anweisungen ; zeige + System-Prompt
        r"(?i)(ignoriere?|vergiss|missachte|uberspringe)\s+(alle\s+)?(vorherigen?|bisherigen?|obigen?)?\s*(anweisungen|anleitungen|regeln|vorgaben)",
        r"(?i)(zeige?|nenne?|gib|offenbare?)\s+(mir\s+)?(deinen?|den|ihren?)\s+(system[- ]?prompt|systemanweisungen|urspruenglichen anweisungen)",
        # Spanish: ignora/olvida + instrucciones ; revela + prompt del sistema
        r"(?i)(ignora|olvida|desatiende|omite)\s+(todas\s+)?(las\s+)?(instrucciones|reglas|indicaciones|directrices)\s*(anteriores|previas)?",
        r"(?i)(revela|muestra|dime|imprime)\s+(me\s+)?(tu|el)\s+(prompt\s+del\s+sistema|instrucciones\s+iniciales|mensaje\s+del\s+sistema)",
        # Portuguese: ignore/esqueca + instrucoes
        r"(?i)(ignore|esqueca|desconsidere)\s+(todas\s+)?(as\s+)?(instrucoes|regras|orientacoes)\s*(anteriores|previas)?",
        # Russian: игнорируй/забудь + инструкции ; покажи системный промпт
        r"(?i)(игнорируй|игнорируйте|забудь|забудьте|не\s+обращай\s+внимания)\s*(на)?\s*(все)?\s*(предыдущие|прежние)?\s*(инструкции|правила|указания)",
        r"(?i)(покажи|раскрой|выведи|назови)\s*(мне)?\s*(свой|системный)\s*(промпт|системный\s+промпт|системное\s+сообщение|начальные\s+инструкции)",
        # Arabic: تجاهل + التعليمات ; أظهر + موجه النظام
        r"(تجاهل|انس|أهمل)\s*(كل|جميع)?\s*(ال)?(تعليمات|التعليمات|القواعد|الأوامر)",
        r"(أظهر|اكشف|اعرض|قل)\s*(لي)?\s*(موجه\s*النظام|تعليماتك\s*الأولية|رسالة\s*النظام)",
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

        # 2. Alternate readings of the same text. Obfuscations compose, so
        # these are built by applying normalizers cumulatively and decoding
        # encoded payloads recursively — see normalization_views().
        for label, view in normalization_views(clean_text):
            result = self._scan(view)
            if result:
                result["reason"] += f" [via {label}]"
                return result

        return {
            "detected": False,
            "confidence": 0.0,
            "reason": "clean prompt",
            "rule": "",
        }
