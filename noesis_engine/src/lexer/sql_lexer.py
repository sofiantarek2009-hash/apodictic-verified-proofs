"""
Apodictic Enterprise Lexical Tokenizer & Parser Generator
Converts plain text, SQL mutations, and ERP payloads into typed lexemes.
Supports fast multi-character lookaheads, nested parenthesis grouping, and strict typing.
"""

from enum import Enum, auto
from typing import List, Tuple, Optional, Any, Dict
from dataclasses import dataclass

class TokenType(Enum):
    KEYWORD = auto()
    IDENTIFIER = auto()
    STRING_LITERAL = auto()
    NUMERIC_LITERAL = auto()
    OPERATOR = auto()
    PUNCTUATION = auto()
    WHITESPACE = auto()
    COMMENT = auto()
    SYMBOL_TOKEN = auto()
    EOF = auto()

@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int
    byte_offset: int

class SqlLexer:
    KEYWORDS = {
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TRUNCATE', 'ALTER',
        'FROM', 'INTO', 'SET', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'IS',
        'NULL', 'TABLE', 'DATABASE', 'SCHEMA', 'CASCADE', 'RESTRICT',
        'BEGIN', 'COMMIT', 'ROLLBACK', 'SAVEPOINT', 'RELEASE', 'TO',
        'VALUES', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER', 'ON', 'AS',
        'GROUP', 'BY', 'ORDER', 'HAVING', 'LIMIT', 'OFFSET', 'FOR', 'UNION'
    }

    OPERATORS = {
        '=', '!=', '<>', '<', '<=', '>', '>=', '+', '-', '*', '/', '%', '||', 'LIKE', 'ILIKE'
    }

    PUNCTUATION = {
        '(', ')', ',', ';', '.', '[', ']', '{', '}'
    }

    def __init__(self, source: str):
        self.source = source
        self.length = len(source)
        self.pos = 0
        self.line = 1
        self.column = 1

    def _peek(self, offset: int = 0) -> str:
        idx = self.pos + offset
        if idx >= self.length:
            return '\0'
        return self.source[idx]

    def _advance(self) -> str:
        if self.pos >= self.length:
            return '\0'
        ch = self.source[self.pos]
        self.pos += 1
        if ch == '\n':
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        return ch

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []

        while self.pos < self.length:
            ch = self._peek()

            # Skip whitespace
            if ch.isspace():
                self._advance()
                continue

            start_col = self.column
            start_line = self.line
            start_pos = self.pos

            # Comments: -- single line or /* multi line */
            if ch == '-' and self._peek(1) == '-':
                comment_val = ""
                while self._peek() not in ('\n', '\0'):
                    comment_val += self._advance()
                tokens.append(Token(TokenType.COMMENT, comment_val, start_line, start_col, start_pos))
                continue

            if ch == '/' and self._peek(1) == '*':
                self._advance()
                self._advance()
                comment_val = "/*"
                while self.pos < self.length:
                    if self._peek() == '*' and self._peek(1) == '/':
                        self._advance()
                        self._advance()
                        comment_val += "*/"
                        break
                    comment_val += self._advance()
                tokens.append(Token(TokenType.COMMENT, comment_val, start_line, start_col, start_pos))
                continue

            # Strings 'single quote' or "double quote"
            if ch in ("'", '"'):
                quote = ch
                self._advance()
                str_val = ""
                while self.pos < self.length:
                    curr = self._advance()
                    if curr == quote:
                        if self._peek() == quote: # Escaped quote
                            str_val += quote
                            self._advance()
                        else:
                            break
                    elif curr == '\\':
                        str_val += self._advance()
                    else:
                        str_val += curr
                tokens.append(Token(TokenType.STRING_LITERAL, str_val, start_line, start_col, start_pos))
                continue

            # Numbers: integers and floating point
            if ch.isdigit():
                num_val = ""
                has_dot = False
                while self._peek().isdigit() or (self._peek() == '.' and not has_dot):
                    if self._peek() == '.':
                        has_dot = True
                    num_val += self._advance()
                tokens.append(Token(TokenType.NUMERIC_LITERAL, num_val, start_line, start_col, start_pos))
                continue

            # Symbol tokens: e.g. <SYM_KEY_1>
            if ch == '<' and self.source[self.pos:].startswith('<SYM_'):
                sym_val = ""
                while self._peek() not in ('>', '\0'):
                    sym_val += self._advance()
                if self._peek() == '>':
                    sym_val += self._advance()
                tokens.append(Token(TokenType.SYMBOL_TOKEN, sym_val, start_line, start_col, start_pos))
                continue

            # Two-character operators: !=, <>, <=, >=, ||
            two_ch = ch + self._peek(1)
            if two_ch in self.OPERATORS:
                self._advance()
                self._advance()
                tokens.append(Token(TokenType.OPERATOR, two_ch, start_line, start_col, start_pos))
                continue

            # Single-character operators
            if ch in self.OPERATORS:
                tokens.append(Token(TokenType.OPERATOR, self._advance(), start_line, start_col, start_pos))
                continue

            # Punctuation
            if ch in self.PUNCTUATION:
                tokens.append(Token(TokenType.PUNCTUATION, self._advance(), start_line, start_col, start_pos))
                continue

            # Identifiers and Keywords
            if ch.isalpha() or ch == '_':
                ident_val = ""
                while self._peek().isalnum() or self._peek() == '_':
                    ident_val += self._advance()

                upper_val = ident_val.upper()
                if upper_val in self.KEYWORDS:
                    tokens.append(Token(TokenType.KEYWORD, upper_val, start_line, start_col, start_pos))
                else:
                    tokens.append(Token(TokenType.IDENTIFIER, ident_val, start_line, start_col, start_pos))
                continue

            # Fallback character
            tokens.append(Token(TokenType.PUNCTUATION, self._advance(), start_line, start_col, start_pos))

        tokens.append(Token(TokenType.EOF, "", self.line, self.column, self.pos))
        return tokens
