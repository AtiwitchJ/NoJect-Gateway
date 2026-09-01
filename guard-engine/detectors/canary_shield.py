import base64
import binascii
import codecs
import html
import re
from typing import Dict, Any, List, Optional

class CanaryShield:
    """
    Guards against system prompt leakage and canary token disclosure in LLM outputs.
    Aligned with ISO/IEC 42001 (Control B.6.2 & B.7.2).
    """

    # Characters an LLM may interleave into a secret when asked to "spell it
    # out" or otherwise obfuscate it. Stripped before the flattened check.
    _SEPARATORS = re.compile(r"[\s\-_.,:;|/\\*+·•]")
    _BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
    _HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){6,}")
    # Six or more space-separated decimal codes — "spell it in ASCII codes".
    _DECIMAL_RUN = re.compile(r"(?:\b\d{2,3}\b[ ,]+){5,}\b\d{2,3}\b")

    def _decoded_views(self, text: str) -> List[str]:
        """Return alternate representations of the response that a leaked
        secret could be hiding in.

        A plain ``token in response_text`` check only catches a verbatim
        leak. A model induced to reveal a canary will often emit it encoded
        or spaced out — base64, hex, ROT13, or s-p-e-l-l-e-d o-u-t — which
        reads identically to a human but defeats substring matching.
        """
        views: List[str] = []
        clean_text = text

        # Zero-width stripped view
        from .text_normalize import normalization_views, strip_zero_width, url_unescape_text
        zw_stripped = strip_zero_width(clean_text)
        views.append(zw_stripped)
        views.append(url_unescape_text(zw_stripped))

        # Separator-stripped view: catches "C-A-N-A-R-Y", "C A N A R Y", etc.
        views.append(self._SEPARATORS.sub("", zw_stripped))
        views.extend(view for _, view in normalization_views(clean_text))

        # ROT13 — trivial to apply, trivial to miss.
        try:
            views.append(codecs.decode(clean_text, "rot_13"))
        except Exception:
            pass

        # Decode embedded base64 runs.
        for match in self._BASE64_RUN.finditer(clean_text):
            candidate = match.group(0)
            try:
                raw = base64.b64decode(candidate, validate=True)
                views.append(raw.decode("utf-8", errors="ignore"))
            except (binascii.Error, ValueError):
                continue

        # Decode embedded hex runs.
        for match in self._HEX_RUN.finditer(clean_text):
            candidate = match.group(0)
            if len(candidate) % 2:
                candidate = candidate[:-1]
            try:
                views.append(bytes.fromhex(candidate).decode("utf-8", errors="ignore"))
            except ValueError:
                continue

        # HTML entities. "CANARY&#95;SECRET" renders as the real token in any
        # HTML context, so it is a genuine disclosure, not an approximation.
        if "&" in clean_text:
            try:
                views.append(html.unescape(clean_text))
            except Exception:
                pass

        # Space-separated decimal character codes ("67 65 78 65 82 89").
        for match in self._DECIMAL_RUN.finditer(clean_text):
            try:
                codes = [int(n) for n in match.group(0).split()]
            except ValueError:
                continue
            if all(32 <= c <= 126 for c in codes):
                views.append("".join(chr(c) for c in codes))

        return views

    # A canary is a secret the model should never emit. Disclosing a
    # substantial prefix of it is already a breach — the attacker can often
    # obtain the remainder, and the leak proves the model is reciting
    # protected context. Require enough characters that ordinary text cannot
    # collide with it by chance.
    _MIN_PARTIAL_LEN = 12

    def _find_leak(self, token: str, response_text: str) -> Optional[str]:
        """Return a short label for how the token leaked, or None."""
        if token in response_text:
            return "verbatim"

        # Reversed disclosure: asking a model to "spell it backwards" is a
        # standard way to smuggle a secret past an exact-match filter.
        reversed_token = token[::-1]
        if reversed_token in response_text:
            return "reversed"

        # Partial disclosure of a long-enough prefix/suffix.
        if len(token) > self._MIN_PARTIAL_LEN:
            if token[: self._MIN_PARTIAL_LEN] in response_text:
                return "partial (prefix)"
            if token[-self._MIN_PARTIAL_LEN :] in response_text:
                return "partial (suffix)"

        from .text_normalize import deleetify
        stripped_token = self._SEPARATORS.sub("", token)
        canonical_token = deleetify(stripped_token).casefold()
        for view in self._decoded_views(response_text):
            if token and token in view:
                return "encoded/obfuscated"
            # The separator-stripped view must be compared against the
            # equally stripped token, or a token containing "_" or "-"
            # (e.g. CANARY_SECRET_ALPHA) never matches its own stripped form.
            if stripped_token and stripped_token in self._SEPARATORS.sub("", view):
                return "encoded/obfuscated"
            if canonical_token and canonical_token in deleetify(self._SEPARATORS.sub("", view)).casefold():
                return "encoded/obfuscated"
        return None

    def inspect(self, response_text: str, canary_tokens: List[str] = None) -> Dict[str, Any]:
        if not response_text:
            return {"detected": False, "threat_type": "NONE", "reason": ""}

        if canary_tokens:
            for token in canary_tokens:
                if not token:
                    continue
                how = self._find_leak(token, response_text)
                if how:
                    return {
                        "detected": True,
                        "threat_type": "CANARY_LEAK",
                        "reason": f"Canary token leaked in model output ({how})",
                        "leaked_token": token,
                    }

        return {
            "detected": False,
            "threat_type": "NONE",
            "reason": "response clean",
        }
