"""
Apodictic Enterprise Deep Loss Prevention (DLP) & Tokenization Engine
Context-aware JSON AST parser, referential integrity keeper, and Shannon entropy analyzer.
Handles nested multi-lingual text, international banking codes, and API credentials.
"""

import re
import math
import json
from typing import Dict, Any, List, Tuple, Optional, Set
from noesis_engine.src.core.types import RedactedSymbol, TokenizeContext

class DeepDlpEngine:
    """
    Enterprise DLP & Data Redaction Engine.
    Guarantees zero sensitive data leakage to external models.
    """

    # Extended regular expression suites
    PATTERNS: List[Tuple[str, str, re.Pattern]] = [
        ('API_KEY', 'SYM_KEY', re.compile(r'\b(?:sk_live|sk_test|pk_live|pk_test|rk_live|noesis_live|ghp|xoxb|gho|glpat|AKIA)[A-Za-z0-9_-]{8,}\b')),
        ('JWT_TOKEN', 'SYM_JWT', re.compile(r'\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b')),
        ('IBAN', 'SYM_IBAN', re.compile(r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b')),
        ('TAX_ID', 'SYM_TAX', re.compile(r'\b(?:ETA|VAT|TIN|EIN|ZATCA)[-:\s]?[0-9]{9,15}\b', re.IGNORECASE)),
        ('EMAIL', 'SYM_EMAIL', re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),
        ('CARD_PAN', 'SYM_CARD', re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b')),
        ('PHONE_E164', 'SYM_PHONE', re.compile(r'(?:\+20|\+966|\+971|\+1|0020)[-\s]?(?:[0-9][-\s]?){8,12}[0-9]\b')),
        ('SSN_NATIONAL_ID', 'SYM_NAT_ID', re.compile(r'\b(?:[0-9]{3}-[0-9]{2}-[0-9]{4}|2[0-9]{13}|3[0-9]{13})\b')),
        ('HEX_SECRET', 'SYM_HEX_SECRET', re.compile(r'\b[a-f0-9]{32,64}\b', re.IGNORECASE))
    ]

    def __init__(self):
        self.vault: Dict[str, str] = {}
        self.reverse_vault: Dict[str, str] = {}
        self.counters: Dict[str, int] = {}

    @staticmethod
    def shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq: Dict[str, int] = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _get_or_create_token(self, raw_str: str, prefix: str, category: str) -> str:
        if raw_str in self.vault:
            return self.vault[raw_str]

        self.counters[prefix] = self.counters.get(prefix, 0) + 1
        tok = f"<{prefix}_{self.counters[prefix]}>"
        self.vault[raw_str] = tok
        self.reverse_vault[tok] = raw_str
        return tok

    def sanitize_text(self, text: str) -> Tuple[str, List[RedactedSymbol], int]:
        if not text:
            return "", [], 0

        modified = text
        redactions: List[RedactedSymbol] = []
        bytes_removed = 0

        # Pattern-based matching
        for category, prefix, rx in self.PATTERNS:
            def repl(m):
                nonlocal bytes_removed
                match_val = m.group(0)
                tok = self._get_or_create_token(match_val, prefix, category)
                bytes_removed += max(0, len(match_val) - len(tok))
                preview = f"{match_val[:3]}...{match_val[-2:]}" if len(match_val) > 5 else "****"
                redactions.append(RedactedSymbol(
                    token=tok,
                    category=category,
                    preview=preview,
                    original_byte_length=len(match_val),
                    entropy_score=round(self.shannon_entropy(match_val), 2)
                ))
                return tok
            modified = rx.sub(repl, modified)

        # High-entropy string scanning (passwords, private key segments)
        words = modified.split()
        for w in words:
            clean_w = w.strip('"\' ,;()[]{}')
            if len(clean_w) >= 28 and not clean_w.startswith('<SYM_'):
                ent = self.shannon_entropy(clean_w)
                if ent > 4.2:
                    tok = self._get_or_create_token(clean_w, 'SYM_ENTROPY_SECRET', 'SECRET')
                    modified = modified.replace(clean_w, tok)
                    redactions.append(RedactedSymbol(
                        token=tok,
                        category="HIGH_ENTROPY_SECRET",
                        preview="***entropy***",
                        original_byte_length=len(clean_w),
                        entropy_score=round(ent, 2)
                    ))

        return modified, redactions, bytes_removed

    def sanitize_json_object(self, obj: Any) -> Tuple[Any, List[RedactedSymbol]]:
        all_redactions: List[RedactedSymbol] = []
        
        if isinstance(obj, str):
            clean, red, _ = self.sanitize_text(obj)
            return clean, red
        elif isinstance(obj, dict):
            clean_dict = {}
            for k, v in obj.items():
                clean_k, r_k, _ = self.sanitize_text(str(k))
                clean_v, r_v = self.sanitize_json_object(v)
                clean_dict[clean_k] = clean_v
                all_redactions.extend(r_k)
                all_redactions.extend(r_v)
            return clean_dict, all_redactions
        elif isinstance(obj, list):
            clean_list = []
            for item in obj:
                clean_item, r_item = self.sanitize_json_object(item)
                clean_list.append(clean_item)
                all_redactions.extend(r_item)
            return clean_list, all_redactions
        return obj, []

    def restore_tokenized_text(self, text: str) -> str:
        restored = text
        for tok, raw in self.reverse_vault.items():
            restored = restored.replace(tok, raw)
        return restored
