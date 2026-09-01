"""
Canary Secret Token Shield (MITRE AML.T0043 / OWASP LLM07:2025)
"""

import base64
import binascii
import codecs
import re
from typing import List, Dict, Any, Optional
from .text_normalize import deleetify, normalization_views, strip_zero_width, url_unescape_text

class CanaryShield:
    _SEPARATORS = re.compile(r"[\s\-_.,:;|/\\*+·•]")
    _BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
    _HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){6,}")

    def _decoded_views(self, text: str) -> List[str]:
        views: List[str] = []
        clean_text = text

        zw_stripped = strip_zero_width(clean_text)
        views.append(zw_stripped)
        views.append(url_unescape_text(zw_stripped))
        views.append(self._SEPARATORS.sub("", zw_stripped))
        views.extend(view for _, view in normalization_views(clean_text))

        try:
            views.append(codecs.decode(clean_text, "rot_13"))
        except Exception:
            pass

        for match in self._BASE64_RUN.finditer(clean_text):
            candidate = match.group(0)
            try:
                raw = base64.b64decode(candidate, validate=True)
                views.append(raw.decode("utf-8", errors="ignore"))
            except (binascii.Error, ValueError):
                continue

        for match in self._HEX_RUN.finditer(clean_text):
            candidate = match.group(0)
            if len(candidate) % 2:
                candidate = candidate[:-1]
            try:
                views.append(bytes.fromhex(candidate).decode("utf-8", errors="ignore"))
            except ValueError:
                continue

        return views

    def _find_leak(self, token: str, response_text: str) -> Optional[str]:
        if token in response_text:
            return "verbatim"

        stripped_token = self._SEPARATORS.sub("", token)
        canonical_token = deleetify(stripped_token).casefold()
        for view in self._decoded_views(response_text):
            if token and token in view:
                return "encoded/obfuscated"
            if stripped_token and stripped_token in self._SEPARATORS.sub("", view):
                return "encoded/obfuscated"
            if canonical_token and canonical_token in deleetify(self._SEPARATORS.sub("", view)).casefold():
                return "encoded/obfuscated"
        return None

    def inspect(self, text: str, canary_tokens: List[str]) -> Dict[str, Any]:
        if not text or not canary_tokens:
            return {"leaked": False, "matched_token": ""}

        for token in canary_tokens:
            if not token:
                continue
            how = self._find_leak(token, text)
            if how:
                return {
                    "leaked": True,
                    "matched_token": token,
                    "reason": f"Canary secret token detected in LLM response output ({how})",
                    "standard_code": "MITRE AML.T0043 / OWASP LLM07:2025"
                }

        return {"leaked": False, "matched_token": ""}
