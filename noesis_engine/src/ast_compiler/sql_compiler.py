"""
Apodictic Enterprise SQL AST Recursive Descent Compiler
Compiles lexical token streams into strongly-typed SQL AST structures.
Performs semantic boundary validation, detects dangerous full-table scans,
and extracts affected columns and predicate bounds.
"""

from typing import List, Optional, Tuple, Dict, Any
from noesis_engine.src.core.types import MutationType, SqlAstNode, ColumnReference, PredicateNode
from noesis_engine.src.lexer.sql_lexer import Token, TokenType, SqlLexer

class AstCompilationError(Exception):
    pass

class SqlAstCompiler:
    def __init__(self, tokens: List[Token], raw_sql: str):
        self.tokens = tokens
        self.raw_sql = raw_sql
        self.pos = 0

    @classmethod
    def compile(cls, sql_text: str) -> SqlAstNode:
        lexer = SqlLexer(sql_text)
        tokens = lexer.tokenize()
        compiler = cls(tokens, sql_text)
        return compiler.parse_statement()

    def _current(self) -> Token:
        if self.pos >= len(self.tokens):
            return self.tokens[-1]
        return self.tokens[self.pos]

    def _peek(self, offset: int = 1) -> Token:
        idx = self.pos + offset
        if idx >= len(self.tokens):
            return self.tokens[-1]
        return self.tokens[idx]

    def _advance(self) -> Token:
        tok = self._current()
        if self.pos < len(self.tokens):
            self.pos += 1
        return tok

    def _match_keyword(self, expected: str) -> bool:
        curr = self._current()
        if curr.type == TokenType.KEYWORD and curr.value.upper() == expected.upper():
            self._advance()
            return True
        return False

    def _expect_keyword(self, expected: str) -> Token:
        curr = self._current()
        if curr.type == TokenType.KEYWORD and curr.value.upper() == expected.upper():
            return self._advance()
        raise AstCompilationError(f"Expected keyword '{expected}', found '{curr.value}' at line {curr.line}, col {curr.column}")

    def parse_statement(self) -> SqlAstNode:
        curr = self._current()
        if curr.type == TokenType.EOF:
            return SqlAstNode(statement_type=MutationType.QUERY, target_tables=[], raw_query=self.raw_sql)

        val = curr.value.upper()
        if val == 'SELECT':
            return self.parse_select()
        elif val == 'INSERT':
            return self.parse_insert()
        elif val == 'UPDATE':
            return self.parse_update()
        elif val == 'DELETE':
            return self.parse_delete()
        elif val == 'DROP':
            return self.parse_drop()
        elif val == 'TRUNCATE':
            return self.parse_truncate()
        elif val == 'ALTER':
            return self.parse_alter()
        else:
            # Generic statement fallback
            return SqlAstNode(
                statement_type=MutationType.QUERY,
                target_tables=[],
                raw_query=self.raw_sql
            )

    def parse_update(self) -> SqlAstNode:
        self._expect_keyword('UPDATE')
        table_tok = self._advance()
        table_name = table_tok.value

        self._expect_keyword('SET')
        modified_cols = []

        # Parse assignments: col = val, ...
        while True:
            col_tok = self._advance()
            modified_cols.append(ColumnReference(table=table_name, column=col_tok.value))
            
            if self._current().type == TokenType.OPERATOR and self._current().value == '=':
                self._advance()
            # Skip value expression until comma, WHERE, or EOF
            while self._current().value.upper() not in (',', 'WHERE') and self._current().type != TokenType.EOF:
                self._advance()

            if self._current().value == ',':
                self._advance()
                continue
            else:
                break

        has_where = False
        predicates = []
        if self._match_keyword('WHERE'):
            has_where = True
            predicates = self.parse_where_predicates(table_name)

        return SqlAstNode(
            statement_type=MutationType.UPDATE,
            target_tables=[table_name],
            modified_columns=modified_cols,
            predicates=predicates,
            has_where_clause=has_where,
            is_unbounded=not has_where,
            raw_query=self.raw_sql
        )

    def parse_delete(self) -> SqlAstNode:
        self._expect_keyword('DELETE')
        self._match_keyword('FROM')
        table_tok = self._advance()
        table_name = table_tok.value

        has_where = False
        predicates = []
        if self._match_keyword('WHERE'):
            has_where = True
            predicates = self.parse_where_predicates(table_name)

        return SqlAstNode(
            statement_type=MutationType.DELETE,
            target_tables=[table_name],
            predicates=predicates,
            has_where_clause=has_where,
            is_unbounded=not has_where,
            raw_query=self.raw_sql
        )

    def parse_drop(self) -> SqlAstNode:
        self._expect_keyword('DROP')
        self._match_keyword('TABLE')
        table_tok = self._advance()
        return SqlAstNode(
            statement_type=MutationType.DROP,
            target_tables=[table_tok.value],
            is_unbounded=True,
            raw_query=self.raw_sql
        )

    def parse_truncate(self) -> SqlAstNode:
        self._expect_keyword('TRUNCATE')
        self._match_keyword('TABLE')
        table_tok = self._advance()
        return SqlAstNode(
            statement_type=MutationType.TRUNCATE,
            target_tables=[table_tok.value],
            is_unbounded=True,
            raw_query=self.raw_sql
        )

    def parse_insert(self) -> SqlAstNode:
        self._expect_keyword('INSERT')
        self._expect_keyword('INTO')
        table_tok = self._advance()
        return SqlAstNode(
            statement_type=MutationType.INSERT,
            target_tables=[table_tok.value],
            raw_query=self.raw_sql
        )

    def parse_select(self) -> SqlAstNode:
        self._expect_keyword('SELECT')
        # Skip projection list to FROM
        tables = []
        while self._current().type != TokenType.EOF:
            if self._current().type == TokenType.KEYWORD and self._current().value.upper() == 'FROM':
                self._advance()
                table_tok = self._advance()
                tables.append(table_tok.value)
                break
            self._advance()

        has_where = False
        predicates = []
        if self._match_keyword('WHERE'):
            has_where = True
            predicates = self.parse_where_predicates(tables[0] if tables else "")

        return SqlAstNode(
            statement_type=MutationType.QUERY,
            target_tables=tables,
            predicates=predicates,
            has_where_clause=has_where,
            raw_query=self.raw_sql
        )

    def parse_where_predicates(self, default_table: str) -> List[PredicateNode]:
        preds = []
        while self._current().type not in (TokenType.EOF, TokenType.PUNCTUATION):
            left_tok = self._advance()
            if self._current().type == TokenType.OPERATOR:
                op_tok = self._advance()
                right_tok = self._advance()
                preds.append(PredicateNode(
                    left=ColumnReference(table=default_table, column=left_tok.value),
                    operator=op_tok.value,
                    right=right_tok.value
                ))
            if self._current().value.upper() in ('AND', 'OR'):
                self._advance()
                continue
            else:
                break
        return preds
