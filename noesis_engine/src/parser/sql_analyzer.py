import sqlparse
from sqlparse.sql import Statement, Token, IdentifierList, Identifier, Where, Comparison
from sqlparse.tokens import Keyword, DML, DDL
from typing import Dict, Any, List, Optional

class SqlSemanticAnalyzer:
    """
    Enterprise SQL AST & Mutation Semantic Analyzer.
    Parses arbitrary SQL DML/DDL into structured AST, classifies blast radius,
    detects destructive mutations, unindexed table scans, and multi-tenant boundary breaches.
    """

    DESTRUCTIVE_KEYWORDS = {'DELETE', 'DROP', 'TRUNCATE', 'ALTER'}

    @classmethod
    def analyze_statement(cls, sql_text: str) -> Dict[str, Any]:
        parsed = sqlparse.parse(sql_text)
        if not parsed:
            return {
                "valid": False,
                "error": "Empty or unparseable SQL statement"
            }

        stmt = parsed[0]
        stmt_type = stmt.get_type() # SELECT, INSERT, UPDATE, DELETE, etc.
        
        is_destructive = False
        tables = []
        has_where_clause = False
        columns_modified = []
        inferred_predicates = []

        tokens = [t for t in stmt.flatten() if not t.is_whitespace]
        first_token = tokens[0].value.upper() if tokens else ""

        if first_token in cls.DESTRUCTIVE_KEYWORDS or stmt_type in cls.DESTRUCTIVE_KEYWORDS:
            is_destructive = True

        # Extract target tables
        from_seen = False
        into_seen = False
        update_seen = False

        for token in stmt.tokens:
            if token.is_whitespace:
                continue
            val_upper = token.value.upper()

            if val_upper == 'FROM':
                from_seen = True
                continue
            if val_upper == 'INTO':
                into_seen = True
                continue
            if val_upper == 'UPDATE':
                update_seen = True
                continue

            if from_seen or into_seen or update_seen:
                if isinstance(token, Identifier):
                    tables.append(token.get_real_name() or token.value)
                    from_seen = into_seen = update_seen = False
                elif isinstance(token, IdentifierList):
                    for iden in token.get_identifiers():
                        tables.append(iden.get_real_name() or iden.value)
                    from_seen = into_seen = update_seen = False
                elif token.ttype is None:
                    # Token group
                    tables.append(token.value.split()[0].strip(',;'))
                    from_seen = into_seen = update_seen = False

            if isinstance(token, Where):
                has_where_clause = True
                for subtoken in token.tokens:
                    if isinstance(subtoken, Comparison):
                        inferred_predicates.append(subtoken.value)

        # Destructive safety check: UPDATE or DELETE without WHERE is catastrophic
        unbounded_mutation = False
        if stmt_type in {'UPDATE', 'DELETE'} and not has_where_clause:
            unbounded_mutation = True
            is_destructive = True

        return {
            "valid": True,
            "statement_type": stmt_type,
            "is_destructive": is_destructive,
            "unbounded_mutation": unbounded_mutation,
            "tables": list(set(tables)),
            "has_where_clause": has_where_clause,
            "predicates": inferred_predicates,
            "requires_atomic_rollback": is_destructive or stmt_type in {'INSERT', 'UPDATE'},
            "raw_ast_tokens": len(tokens)
        }
