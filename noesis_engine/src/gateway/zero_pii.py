import re
import math
from typing import Dict, Any, List, Tuple

# Shannon entropy calculator for detecting raw high-entropy API keys, secrets, and bearer tokens
def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

class ZeroPIIGateway:
    """
    Enterprise-Grade Zero-PII Gateway & Secret Sanitizer.
    Performs context-aware JSON AST and textual tokenization with referential integrity.
    Replaces sensitive data with bijective cryptographically mapped vault tokens <SYM_*>.
    """
    PATTERNS: List[Tuple[str, str, re.Pattern]] = [
        ('API_KEY', 'SYM_KEY', re.compile(r'\b(?:sk_live|sk_test|pk_live|pk_test|rk_live|noesis_live|ghp|xoxb)_[A-Za-z0-9]{8,}\b')),
        ('HEX_SECRET', 'SYM_HEX_SECRET', re.compile(r'\b[a-f0-9]{32,64}\b', re.IGNORECASE)),
        ('JWT_TOKEN', 'SYM_JWT', re.compile(r'\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b')),
        ('IBAN', 'SYM_IBAN', re.compile(r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,28}\b')),
        ('TAX_ID', 'SYM_TAX', re.compile(r'\b(?:ETA|VAT|TIN|EIN|ZATCA)[-:\s]?[0-9]{9,15}\b', re.IGNORECASE)),
        ('EMAIL', 'SYM_EMAIL', re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),
        ('CARD_PAN', 'SYM_CARD', re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b')),
        ('PHONE_E164', 'SYM_PHONE', re.compile(r'(?:\+20|\+966|\+1|0020)[-\s]?(?:[0-9][-\s]?){8,12}[0-9]\b')),
        ('SSN', 'SYM_SSN', re.compile(r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'))
    ]

    def __init__(self):
        self.vault: Dict[str, str] = {}
        self.reverse_vault: Dict[str, str] = {}
        self.counters: Dict[str, int] = {}

    def _get_or_create_token(self, raw_val: str, prefix: str, category: str) -> str:
        if raw_val in self.vault:
            return self.vault[raw_val]
        
        self.counters[prefix] = self.counters.get(prefix, 0) + 1
        idx = self.counters[prefix]
        token = f"<{prefix}_{idx}>"
        self.vault[raw_val] = token
        self.reverse_vault[token] = raw_val
        return token

    def sanitize_string(self, text: str) -> Tuple[str, List[Dict[str, Any]], int]:
        if not text:
            return "", [], 0
            
        modified = text
        redacted_items = []
        bytes_removed = 0

        # 1. Pattern-based sanitization
        for category, prefix, regex in self.PATTERNS:
            def replacer(match):
                nonlocal bytes_removed
                raw = match.group(0)
                token = self._get_or_create_token(raw, prefix, category)
                bytes_removed += max(0, len(raw) - len(token))
                redacted_items.append({
                    "token": token,
                    "category": category,
                    "length": len(raw),
                    "preview": f"{raw[:3]}...{raw[-2:]}" if len(raw) > 5 else "***"
                })
                return token
            modified = regex.sub(replacer, modified)

        # 2. Entropy-based high-entropy secret detection (tokens with entropy > 4.5 and len >= 24)
        words = modified.split()
        for i, word in enumerate(words):
            clean_word = word.strip('"\' ,;()[]{}')
            if len(clean_word) >= 24 and not clean_word.startswith('<SYM_'):
                ent = calculate_shannon_entropy(clean_word)
                if ent > 4.5:
                    token = self._get_or_create_token(clean_word, 'SYM_ENTROPY_SECRET', 'SECRET')
                    modified = modified.replace(clean_word, token)
                    redacted_items.append({
                        "token": token,
                        "category": "HIGH_ENTROPY_SECRET",
                        "length": len(clean_word),
                        "entropy": round(ent, 2)
                    })

        return modified, redacted_items, bytes_removed

    def sanitize_payload(self, obj: Any) -> Tuple[Any, List[Dict[str, Any]]]:
        all_redactions = []
        if isinstance(obj, str):
            sanitized, redactions, _ = self.sanitize_string(obj)
            return sanitized, redactions
        elif isinstance(obj, dict):
            new_dict = {}
            for k, v in obj.items():
                clean_k, r_k, _ = self.sanitize_string(str(k))
                clean_v, r_v = self.sanitize_payload(v)
                new_dict[clean_k] = clean_v
                all_redactions.extend(r_k)
                all_redactions.extend(r_v)
            return new_dict, all_redactions
        elif isinstance(obj, list):
            new_list = []
            for item in obj:
                clean_item, r_item = self.sanitize_payload(item)
                new_list.append(clean_item)
                all_redactions.extend(r_item)
            return new_list, all_redactions
        return obj, []

    def restore_payload(self, text: str) -> str:
        restored = text
        for token, raw in self.reverse_vault.items():
            restored = restored.replace(token, raw)
        return restored
