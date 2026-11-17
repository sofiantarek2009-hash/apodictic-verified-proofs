"""
Apodictic SQL-to-SSA Symbolic Lifter.
Parses multi-statement SQL transactions (BEGIN; UPDATE ...; INSERT ...; DELETE ...; COMMIT;)
into Static Single Assignment (SSA) relational mutation records.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class SymbolicStatementKind(str, Enum):
    BEGIN = "BEGIN"
    COMMIT = "COMMIT"
    ROLLBACK = "ROLLBACK"
    UPDATE = "UPDATE"
    INSERT = "INSERT"
    DELETE = "DELETE"
    SELECT = "SELECT"


@dataclass(frozen=True)
class SymbolicAssignment:
    column: str
    expression: str  # e.g., "balance - 5000", "balance + 5000", "1000"


@dataclass
class SymbolicSqlStatement:
    ssa_version: int
    kind: SymbolicStatementKind
    table: Optional[str] = None
    assignments: List[SymbolicAssignment] = field(default_factory=list)
    where_predicate: Optional[str] = None
    insert_columns: List[str] = field(default_factory=list)
    insert_values: List[str] = field(default_factory=list)
    raw_sql: str = ""


class SqlSsaLifter:
    """
    Lifts raw multi-statement SQL scripts into SSA-versioned symbolic statements.
    """

    UPDATE_RE = re.compile(
        r"^\s*UPDATE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+SET\s+(.+?)(?:\s+WHERE\s+(.+?))?\s*$",
        re.IGNORECASE | re.DOTALL,
    )
    INSERT_RE = re.compile(
        r"^\s*INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)\s*$",
        re.IGNORECASE | re.DOTALL,
    )
    DELETE_RE = re.compile(
        r"^\s*DELETE\s+FROM\s+([a-zA-Z_][a-zA-Z0-9_]*)(?:\s+WHERE\s+(.+?))?\s*$",
        re.IGNORECASE | re.DOTALL,
    )

    def lift_transaction(self, sql_script: str) -> List[SymbolicSqlStatement]:
        statements: List[SymbolicSqlStatement] = []
        raw_parts = [p.strip() for p in sql_script.split(";") if p.strip()]
        version_counter: Dict[str, int] = {}

        for raw in raw_parts:
            upper = raw.upper()
            if upper in ("BEGIN", "BEGIN TRANSACTION", "START TRANSACTION"):
                statements.append(SymbolicSqlStatement(0, SymbolicStatementKind.BEGIN, raw_sql=raw))
                continue
            if upper in ("COMMIT", "COMMIT TRANSACTION"):
                statements.append(SymbolicSqlStatement(0, SymbolicStatementKind.COMMIT, raw_sql=raw))
                continue
            if upper in ("ROLLBACK", "ABORT"):
                statements.append(SymbolicSqlStatement(0, SymbolicStatementKind.ROLLBACK, raw_sql=raw))
                continue

            m_upd = self.UPDATE_RE.match(raw)
            if m_upd:
                table = m_upd.group(1).lower()
                set_clause = m_upd.group(2)
                where_clause = m_upd.group(3)
                ver = version_counter.get(table, 0) + 1
                version_counter[table] = ver

                assigns: List[SymbolicAssignment] = []
                for part in set_clause.split(","):
                    if "=" in part:
                        col, expr = part.split("=", 1)
                        assigns.append(SymbolicAssignment(col.strip().lower(), expr.strip()))

                statements.append(
                    SymbolicSqlStatement(
                        ssa_version=ver,
                        kind=SymbolicStatementKind.UPDATE,
                        table=table,
                        assignments=assigns,
                        where_predicate=where_clause.strip() if where_clause else None,
                        raw_sql=raw,
                    )
                )
                continue

            m_ins = self.INSERT_RE.match(raw)
            if m_ins:
                table = m_ins.group(1).lower()
                cols = [c.strip().lower() for c in m_ins.group(2).split(",")]
                vals = [v.strip().strip("'\"") for v in m_ins.group(3).split(",")]
                ver = version_counter.get(table, 0) + 1
                version_counter[table] = ver
                statements.append(
                    SymbolicSqlStatement(
                        ssa_version=ver,
                        kind=SymbolicStatementKind.INSERT,
                        table=table,
                        insert_columns=cols,
                        insert_values=vals,
                        raw_sql=raw,
                    )
                )
                continue

            m_del = self.DELETE_RE.match(raw)
            if m_del:
                table = m_del.group(1).lower()
                where_clause = m_del.group(2)
                ver = version_counter.get(table, 0) + 1
                version_counter[table] = ver
                statements.append(
                    SymbolicSqlStatement(
                        ssa_version=ver,
                        kind=SymbolicStatementKind.DELETE,
                        table=table,
                        where_predicate=where_clause.strip() if where_clause else None,
                        raw_sql=raw,
                    )
                )
                continue

            statements.append(SymbolicSqlStatement(0, SymbolicStatementKind.SELECT, raw_sql=raw))

        return statements
