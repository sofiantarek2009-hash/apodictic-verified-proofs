"""
Apodictic Core Domain Types & Data Contracts
High-impact, strongly-typed representations for transactions, invariants,
AST nodes, execution graphs, cryptographic proofs, and saga coordination states.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Any, Optional, Set, Tuple, Union
import time
import uuid
import hashlib
import json

class IsolationLevel(Enum):
    READ_UNCOMMITTED = "READ_UNCOMMITTED"
    READ_COMMITTED = "READ_COMMITTED"
    REPEATABLE_READ = "REPEATABLE_READ"
    SERIALIZABLE = "SERIALIZABLE"

class MutationType(Enum):
    QUERY = "QUERY"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    DROP = "DROP"
    TRUNCATE = "TRUNCATE"
    ALTER = "ALTER"
    RPC_CALL = "RPC_CALL"
    ERP_ACTION = "ERP_ACTION"

class TargetSystemType(Enum):
    POSTGRESQL = "POSTGRESQL"
    MYSQL = "MYSQL"
    ODOO_V18 = "ODOO_V18"
    NETSUITE = "NETSUITE"
    SNOWFLAKE = "SNOWFLAKE"
    STRIPE = "STRIPE"

class Verdict(Enum):
    SAT = "SAT"
    UNSAT = "UNSAT"
    UNKNOWN = "UNKNOWN"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"

class SagaStepStatus(Enum):
    PENDING = "PENDING"
    FORWARD_STAGED = "FORWARD_STAGED"
    COMMITTED = "COMMITTED"
    COMPENSATION_STAGED = "COMPENSATION_STAGED"
    COMPENSATED = "COMPENSATED"
    FAILED = "FAILED"

@dataclass
class ColumnReference:
    table: str
    column: str
    alias: Optional[str] = None
    data_type: Optional[str] = None

@dataclass
class PredicateNode:
    left: Union[ColumnReference, str, float, int]
    operator: str # =, !=, >, <, >=, <=, IN, LIKE, IS
    right: Union[ColumnReference, str, float, int, List[Any]]

@dataclass
class SqlAstNode:
    statement_type: MutationType
    target_tables: List[str]
    modified_columns: List[ColumnReference] = field(default_factory=list)
    predicates: List[PredicateNode] = field(default_factory=list)
    has_where_clause: bool = False
    is_unbounded: bool = False
    estimated_rows_affected: int = 1
    raw_query: str = ""

@dataclass
class DagStep:
    step_id: str
    name: str
    target_system: TargetSystemType
    action: str
    amount: float
    account_id: str
    requires_approval: bool = False
    invariants: List[str] = field(default_factory=list)
    payload: Dict[str, Any] = field(default_factory=dict)
    reversal_payload: Optional[Dict[str, Any]] = None
    dependencies: List[str] = field(default_factory=list)

@dataclass
class InvariantRule:
    rule_id: str
    name: str
    description: str
    logic_smt2: str
    enforce_blocking: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ProofCertificate:
    proof_id: str
    verdict: Verdict
    solver_engine: str
    z3_solve_ms: float
    total_latency_ms: float
    unsat_core: List[str] = field(default_factory=list)
    sha256_hash: str = ""
    timestamp_ns: int = field(default_factory=time.time_ns)

    def calculate_digest(self, smt_formula: str) -> str:
        raw = f"{self.proof_id}:{self.verdict.value}:{smt_formula}:{self.timestamp_ns}"
        self.sha256_hash = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        return self.sha256_hash

@dataclass
class RedactedSymbol:
    token: str
    category: str
    preview: str
    original_byte_length: int
    entropy_score: float = 0.0

@dataclass
class TokenizeContext:
    original_text: str
    sanitized_text: str
    vault: Dict[str, str] = field(default_factory=dict)
    reverse_vault: Dict[str, str] = field(default_factory=dict)
    redactions: List[RedactedSymbol] = field(default_factory=list)
    duration_us: float = 0.0
    bytes_removed: int = 0

@dataclass
class SagaExecutionRecord:
    saga_id: str
    batch_id: str
    created_at: float
    steps: List[DagStep]
    status_map: Dict[str, SagaStepStatus] = field(default_factory=dict)
    compensation_journal: List[Dict[str, Any]] = field(default_factory=list)
    is_terminal: bool = False
