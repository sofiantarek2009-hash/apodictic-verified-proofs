#!/usr/bin/env python3
"""
Apodictic Standalone Z3 5.4.1 Formal Verification Kernel & SQLite WAL Enclave.
Self-contained engine shipped directly inside @apodictic/sdk so npm/npx installs
run full Z3 theorem proving, SQL AST inspection, PII scrubbing, persistent rollback,
3-way match, indirect tax verification, bi-temporal queries, and WORM SHA-256 sealing
without requiring the monorepo.
"""
import base64
from collections import deque
from dataclasses import dataclass
import hashlib
import json
import math
import os
import re
import sqlite3
import string
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import z3
except ImportError:
    msg = (
        "Python z3-solver not found. Install with: pip install z3-solver, "
        "or pass --endpoint https://www.apodictic.dev/api/v1/enclave"
    )
    sys.stderr.write(json.dumps({"error": msg}) + "\n")
    sys.stderr.flush()
    sys.exit(2)

try:
    import sqlglot
    from sqlglot import exp as sg_exp
    HAS_SQLGLOT = True
except Exception:
    HAS_SQLGLOT = False

ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\uFEFF\u00AD]")
SQL_COMMENT_RE = re.compile(r"--[^\n]*|/\*[\s\S]*?\*/")
STRING_LIT_RE = re.compile(r"'(?:''|[^'])*'")

_IBAN_ALPHA_MAP: Dict[int, str] = {
    ord(ch): str(idx) for idx, ch in enumerate(string.digits + string.ascii_uppercase)
}


def validate_iban_mod97(candidate: str) -> bool:
    """ISO-7064 Mod-97-10 IBAN mathematical checksum verification."""
    cleaned = re.sub(r"[\s-]+", "", candidate or "").upper()
    if len(cleaned) < 15 or len(cleaned) > 34:
        return False
    if not (cleaned[:2].isalpha() and cleaned[2:4].isdigit() and cleaned[4:].isalnum()):
        return False
    try:
        rearranged = cleaned[4:] + cleaned[:2] + "00"
        numeric = int(rearranged.translate(_IBAN_ALPHA_MAP))
        return f"{98 - (numeric % 97):0>2}" == cleaned[2:4]
    except Exception:
        return False


def validate_luhn_pan(candidate: str) -> bool:
    """Luhn Mod-10 payment card PAN checksum verification."""
    digits_str = re.sub(r"[\s-]+", "", candidate or "")
    if not digits_str.isdigit() or len(digits_str) < 13 or len(digits_str) > 19:
        return False
    digits = [int(d) for d in digits_str]
    checksum = sum(digits[-1::-2])
    for d in digits[-2::-2]:
        doubled = d * 2
        checksum += doubled - 9 if doubled > 9 else doubled
    return checksum > 0 and (checksum % 10 == 0)


PII_RULES = [
    ("SECRET", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")),
    ("SECRET", re.compile(r"\b(?:sk_live|sk_test|pk_live|pk_test|rk_live|rk_test|ghp|gho|glpat|xoxb|xoxp|odoo_rpc_live)_[A-Za-z0-9_-]{6,}\b")),
    ("SECRET", re.compile(r"\bAIzaSy[A-Za-z0-9_-]{20,40}\b")),
    ("SECRET", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SECRET", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("DB_URL", re.compile(r"\bpostgres(?:ql)?://[^\s'\"]+@[^\s'\"]+\b", re.I)),
    ("IBAN", re.compile(r"\b[A-Za-z]{2}\d{2}(?:[A-Za-z0-9]{10,30}|(?:[\s-][A-Za-z0-9]{4}){2,7}(?:[\s-][A-Za-z0-9]{1,4})?)\b")),
    ("CARD", re.compile(r"\b(?:\d{4}[-\s]?\d{6}[-\s]?\d{5}|\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,7}|\d{13,19})\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("TAX", re.compile(r"\b(?:ETA-\d{6,12}|TIN\s*\d{2}-\d{7}|\d{3}-\d{3}-\d{3})\b")),
]

SEVERITY_ORDER = {
    "DROP": 7,
    "TRUNCATE": 6,
    "DELETE": 5,
    "ALTER": 4,
    "UPDATE": 3,
    "INSERT": 2,
    "QUERY": 0,
}

GENESIS_HASH = "0" * 64


def rfc6962_leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    if n <= 1:
        return 0
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def rfc6962_tree_hash(leaves: List[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _largest_power_of_two_less_than(n)
    return rfc6962_node_hash(rfc6962_tree_hash(leaves[:k]), rfc6962_tree_hash(leaves[k:]))


def rfc6962_audit_path(m: int, leaves: List[bytes]) -> List[bytes]:
    n = len(leaves)
    if n <= 1 or m >= n:
        return []
    k = _largest_power_of_two_less_than(n)
    if m < k:
        return rfc6962_audit_path(m, leaves[:k]) + [rfc6962_tree_hash(leaves[k:])]
    return rfc6962_audit_path(m - k, leaves[k:]) + [rfc6962_tree_hash(leaves[:k])]


def rfc6962_verify_inclusion(
    leaf_hash: bytes,
    leaf_index: int,
    tree_size: int,
    audit_path: List[bytes],
    expected_root: bytes,
) -> bool:
    if leaf_index >= tree_size or tree_size <= 0:
        return False
    if tree_size == 1:
        return len(audit_path) == 0 and leaf_hash == expected_root

    def _reconstruct(m: int, n: int, leaf: bytes, path: List[bytes]) -> Optional[bytes]:
        if n == 1:
            return leaf if len(path) == 0 else None
        if not path:
            return None
        k = _largest_power_of_two_less_than(n)
        sibling = path[-1]
        sub = path[:-1]
        if m < k:
            left = _reconstruct(m, k, leaf, sub)
            return rfc6962_node_hash(left, sibling) if left else None
        right = _reconstruct(m - k, n - k, leaf, sub)
        return rfc6962_node_hash(sibling, right) if right else None

    computed = _reconstruct(leaf_index, tree_size, leaf_hash, audit_path)
    return computed == expected_root


POLICY_STMT_RE = re.compile(
    r"\b(?P<effect>permit|forbid)\s*\((?P<head>[^)]*)\)\s*"
    r"(?:(?P<guard_kind>when|unless)\s*\{\s*(?P<guard_expr>[^}]*)\s*\})?\s*;",
    re.I | re.S,
)
POLICY_ACTION_RE = re.compile(r'Action::"([^"]+)"', re.I)
POLICY_PRINCIPAL_RE = re.compile(r'principal\s*(?P<op>in|==)\s*(?P<target>[A-Za-z0-9_]+::"[^"]+")', re.I)
POLICY_RESOURCE_RE = re.compile(r'resource\s*(?P<op>in|==)\s*(?P<target>[A-Za-z0-9_]+::"[^"]+")', re.I)

DEFAULT_ENTERPRISE_POLICY = """
permit(
  principal,
  action,
  resource
) when {
  context.amount >= 0 &&
  context.post_balance >= context.min_reserve &&
  (context.amount <= context.spending_limit || context.cfo_signed == true)
};

forbid(
  principal,
  action in [Action::"DROP", Action::"TRUNCATE", Action::"DELETE", Action::"ALTER"],
  resource
) unless {
  context.reversal_armed == true
};
""".strip()


class EntityHierarchyGraph:
    def __init__(self, parent_edges: Optional[Dict[str, List[str]]] = None):
        self.parents: Dict[str, List[str]] = {}
        if parent_edges:
            for child, plist in parent_edges.items():
                self.parents[str(child)] = [str(p) for p in plist]

    def ancestors(self, entity: str) -> Set[str]:
        visited: Set[str] = set()
        queue = deque([entity])
        while queue:
            curr = queue.popleft()
            if curr in visited:
                continue
            visited.add(curr)
            for p in self.parents.get(curr, []):
                if p not in visited:
                    queue.append(p)
        return visited

    def is_member_of(self, entity: Optional[str], target: Optional[str], op: Optional[str]) -> bool:
        if not op or not target:
            return True
        if not entity:
            return False
        if op == "==":
            return entity == target
        if op == "in":
            return target in self.ancestors(entity)
        return False


class GuardCompileError(ValueError):
    """Raised when a policy guard expression contains invalid syntax or unknown fields."""


@dataclass
class _LiteralNode:
    value: Union[bool, float, str]


@dataclass
class _VarNode:
    name: str


@dataclass
class _UnaryNode:
    op: str
    operand: Any


@dataclass
class _BinaryNode:
    op: str
    left: Any
    right: Any


_GUARD_TOKEN_SPEC = [
    ("SKIP", r"\s+"),
    ("OR", r"\|\|"),
    ("AND", r"&&"),
    ("EQ", r"=="),
    ("NE", r"!="),
    ("LE", r"<="),
    ("GE", r">="),
    ("LT", r"<"),
    ("GT", r">"),
    ("NOT", r"!"),
    ("PLUS", r"\+"),
    ("MINUS", r"-"),
    ("STAR", r"\*"),
    ("SLASH", r"/"),
    ("LPAREN", r"\("),
    ("RPAREN", r"\)"),
    ("NUMBER", r"\d+(?:\.\d+)?"),
    ("STRING", r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''),
    ("IDENT", r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"),
]
_GUARD_TOKEN_RE = re.compile("|".join(f"(?P<{name}>{pat})" for name, pat in _GUARD_TOKEN_SPEC))


class PolicyGuardZ3Compiler:
    """Zero-eval recursive-descent parser and symbolic Z3 5.4.1 compiler for policy guards."""

    def __init__(self, expr: str):
        self.tokens = self._tokenize(expr)
        self.pos = 0

    @staticmethod
    def _tokenize(expr: str) -> List[Tuple[str, str]]:
        tokens: List[Tuple[str, str]] = []
        idx = 0
        n = len(expr)
        while idx < n:
            m = _GUARD_TOKEN_RE.match(expr, idx)
            if not m:
                raise GuardCompileError(f"Unexpected token at position {idx}")
            kind = m.lastgroup
            val = m.group()
            idx = m.end()
            if kind != "SKIP":
                tokens.append((kind or "", val))
        return tokens

    def _peek(self) -> Optional[Tuple[str, str]]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self, expected: Optional[str] = None) -> Tuple[str, str]:
        tok = self._peek()
        if tok is None:
            raise GuardCompileError("Unexpected end of guard expression")
        if expected and tok[0] != expected:
            raise GuardCompileError(f"Expected {expected}, got {tok[0]}")
        self.pos += 1
        return tok

    @classmethod
    def parse(cls, expr: str) -> Any:
        stripped = (expr or "").strip()
        if not stripped:
            return _LiteralNode(True)
        parser = cls(stripped)
        ast = parser._parse_or()
        if parser._peek() is not None:
            raise GuardCompileError(f"Trailing tokens: {parser._peek()}")
        return ast

    def _parse_or(self) -> Any:
        node = self._parse_and()
        while (tok := self._peek()) is not None and tok[0] == "OR":
            self._consume()
            node = _BinaryNode("||", node, self._parse_and())
        return node

    def _parse_and(self) -> Any:
        node = self._parse_cmp()
        while (tok := self._peek()) is not None and tok[0] == "AND":
            self._consume()
            node = _BinaryNode("&&", node, self._parse_cmp())
        return node

    def _parse_cmp(self) -> Any:
        node = self._parse_add()
        while (tok := self._peek()) is not None and tok[0] in ("EQ", "NE", "LT", "LE", "GT", "GE"):
            _, op = self._consume()
            node = _BinaryNode(op, node, self._parse_add())
        return node

    def _parse_add(self) -> Any:
        node = self._parse_mul()
        while (tok := self._peek()) is not None and tok[0] in ("PLUS", "MINUS"):
            _, op = self._consume()
            node = _BinaryNode(op, node, self._parse_mul())
        return node

    def _parse_mul(self) -> Any:
        node = self._parse_unary()
        while (tok := self._peek()) is not None and tok[0] in ("STAR", "SLASH"):
            _, op = self._consume()
            node = _BinaryNode(op, node, self._parse_unary())
        return node

    def _parse_unary(self) -> Any:
        tok = self._peek()
        if tok is not None and tok[0] in ("NOT", "MINUS"):
            _, op = self._consume()
            return _UnaryNode(op, self._parse_unary())
        return self._parse_primary()

    def _parse_primary(self) -> Any:
        tok = self._peek()
        if tok is None:
            raise GuardCompileError("Expected operand")
        kind, val = tok
        if kind == "LPAREN":
            self._consume("LPAREN")
            node = self._parse_or()
            self._consume("RPAREN")
            return node
        if kind == "NUMBER":
            self._consume()
            return _LiteralNode(float(val))
        if kind == "STRING":
            self._consume()
            return _LiteralNode(val[1:-1].replace('\\"', '"').replace("\\'", "'"))
        if kind == "IDENT":
            self._consume()
            low = val.lower()
            if low == "true":
                return _LiteralNode(True)
            if low == "false":
                return _LiteralNode(False)
            if low in ("and", "or", "not"):
                raise GuardCompileError(f"Unsupported keyword operator {val!r}")
            field_name = val[len("context."):] if val.startswith("context.") else val
            return _VarNode(field_name)
        raise GuardCompileError(f"Unexpected token {tok!r}")

    @classmethod
    def eval_ast(cls, node: Any, ctx_map: Dict[str, Any]) -> Any:
        if isinstance(node, _LiteralNode):
            return node.value
        if isinstance(node, _VarNode):
            if node.name not in ctx_map:
                raise GuardCompileError(f"Unbound context field: {node.name}")
            return ctx_map[node.name]
        if isinstance(node, _UnaryNode):
            val = cls.eval_ast(node.operand, ctx_map)
            if node.op == "!":
                if not isinstance(val, bool):
                    raise GuardCompileError("Boolean NOT requires boolean operand")
                return not val
            if node.op == "-":
                if isinstance(val, bool) or not isinstance(val, (int, float)):
                    raise GuardCompileError("Unary minus requires numeric operand")
                return -float(val)
        if isinstance(node, _BinaryNode):
            if node.op == "&&":
                return bool(cls.eval_ast(node.left, ctx_map)) and bool(cls.eval_ast(node.right, ctx_map))
            if node.op == "||":
                return bool(cls.eval_ast(node.left, ctx_map)) or bool(cls.eval_ast(node.right, ctx_map))
            left = cls.eval_ast(node.left, ctx_map)
            right = cls.eval_ast(node.right, ctx_map)
            if node.op == "+":
                return float(left) + float(right)
            if node.op == "-":
                return float(left) - float(right)
            if node.op == "*":
                return float(left) * float(right)
            if node.op == "/":
                r_num = float(right)
                if r_num == 0.0:
                    raise GuardCompileError("Division by zero")
                return float(left) / r_num
            if node.op == "==":
                return left == right
            if node.op == "!=":
                return left != right
            if isinstance(left, bool) or isinstance(right, bool):
                raise GuardCompileError("Ordering comparison cannot accept boolean")
            if node.op == "<":
                return float(left) < float(right)
            if node.op == "<=":
                return float(left) <= float(right)
            if node.op == ">":
                return float(left) > float(right)
            if node.op == ">=":
                return float(left) >= float(right)
        raise GuardCompileError(f"Unsupported AST node: {node!r}")

    @classmethod
    def compile_z3(cls, node: Any, z3_ctx: z3.Context, z3_vars: Dict[str, Any]) -> Any:
        if isinstance(node, _LiteralNode):
            if isinstance(node.value, bool):
                return z3.BoolVal(node.value, ctx=z3_ctx)
            if isinstance(node.value, (int, float)):
                return z3.RealVal(str(node.value), ctx=z3_ctx)
            return z3.StringVal(str(node.value), ctx=z3_ctx)
        if isinstance(node, _VarNode):
            if node.name not in z3_vars:
                raise GuardCompileError(f"Unbound Z3 context symbol: {node.name}")
            return z3_vars[node.name]
        if isinstance(node, _UnaryNode):
            sub = cls.compile_z3(node.operand, z3_ctx, z3_vars)
            if node.op == "!":
                if not z3.is_bool(sub):
                    raise GuardCompileError("Z3 NOT requires BoolRef")
                return z3.Not(sub)
            if node.op == "-":
                if not z3.is_arith(sub):
                    raise GuardCompileError("Z3 unary minus requires ArithRef")
                return -sub
        if isinstance(node, _BinaryNode):
            lhs = cls.compile_z3(node.left, z3_ctx, z3_vars)
            rhs = cls.compile_z3(node.right, z3_ctx, z3_vars)
            if node.op == "&&":
                if not (z3.is_bool(lhs) and z3.is_bool(rhs)):
                    raise GuardCompileError("Z3 && requires BoolRef")
                return z3.And(lhs, rhs)
            if node.op == "||":
                if not (z3.is_bool(lhs) and z3.is_bool(rhs)):
                    raise GuardCompileError("Z3 || requires BoolRef")
                return z3.Or(lhs, rhs)
            if node.op in ("+", "-", "*", "/"):
                if not (z3.is_arith(lhs) and z3.is_arith(rhs)):
                    raise GuardCompileError("Z3 arithmetic requires ArithRef")
                if node.op == "+":
                    return lhs + rhs
                if node.op == "-":
                    return lhs - rhs
                if node.op == "*":
                    return lhs * rhs
                return lhs / rhs
            if node.op == "==":
                if lhs.sort() != rhs.sort():
                    raise GuardCompileError("Z3 == sort mismatch")
                return lhs == rhs
            if node.op == "!=":
                if lhs.sort() != rhs.sort():
                    raise GuardCompileError("Z3 != sort mismatch")
                return lhs != rhs
            if not (z3.is_arith(lhs) and z3.is_arith(rhs)):
                raise GuardCompileError("Z3 ordering requires ArithRef")
            if node.op == "<":
                return lhs < rhs
            if node.op == "<=":
                return lhs <= rhs
            if node.op == ">":
                return lhs > rhs
            if node.op == ">=":
                return lhs >= rhs
        raise GuardCompileError(f"Unsupported Z3 AST node: {node!r}")


def evaluate_policy_z3(
    policy_text: str,
    action: str,
    context: Dict[str, Any],
    principal: Optional[str] = None,
    resource: Optional[str] = None,
    entity_hierarchy: Optional[Dict[str, List[str]]] = None,
) -> Dict[str, Any]:
    src = (policy_text or DEFAULT_ENTERPRISE_POLICY).strip()
    norm_action = (action or "UPDATE").upper()
    dag = EntityHierarchyGraph(entity_hierarchy or context.get("entity_hierarchy"))
    eff_principal = principal or context.get("principal")
    eff_resource = resource or context.get("resource")

    amount = float(context.get("amount", 0.0))
    current_balance = float(context.get("current_balance", 250000.0))
    min_reserve = float(context.get("min_reserve", 50000.0))
    spending_limit = float(context.get("spending_limit", 50000.0))
    cfo_signed = bool(context.get("cfo_signed", False))
    reversal_armed = bool(context.get("reversal_armed", True))
    post_balance = current_balance - amount

    eval_ctx: Dict[str, Any] = {
        "amount": amount,
        "current_balance": current_balance,
        "post_balance": post_balance,
        "min_reserve": min_reserve,
        "spending_limit": spending_limit,
        "cfo_signed": cfo_signed,
        "reversal_armed": reversal_armed,
    }
    for k, v in (context or {}).items():
        if k in eval_ctx or k in ("entity_hierarchy", "principal", "resource"):
            continue
        if isinstance(v, bool):
            eval_ctx[k] = v
        elif isinstance(v, (int, float)):
            eval_ctx[k] = float(v)
        elif isinstance(v, str):
            eval_ctx[k] = v

    z3_ctx = z3.Context()
    s = z3.Solver(ctx=z3_ctx)
    z3_vars: Dict[str, Any] = {}
    for k, v in eval_ctx.items():
        if isinstance(v, bool):
            z_var = z3.Bool(f"ctx_{k}", ctx=z3_ctx)
            s.add(z_var == z3.BoolVal(v, ctx=z3_ctx))
        elif isinstance(v, (int, float)):
            z_var = z3.Real(f"ctx_{k}", ctx=z3_ctx)
            if k != "post_balance":
                s.add(z_var == z3.RealVal(str(v), ctx=z3_ctx))
        else:
            z_var = z3.String(f"ctx_{k}", ctx=z3_ctx)
            s.add(z_var == z3.StringVal(str(v), ctx=z3_ctx))
        z3_vars[k] = z_var
    if "post_balance" in z3_vars and "current_balance" in z3_vars and "amount" in z3_vars:
        s.add(z3_vars["post_balance"] == z3_vars["current_balance"] - z3_vars["amount"])

    permit_matched: List[str] = []
    forbid_triggered: List[str] = []
    matching_permit_z3: List[z3.BoolRef] = []
    matching_forbid_z3: List[z3.BoolRef] = []
    hierarchy_scope_checked = False
    any_permit_scope_matched = False
    any_permit_scope_failed = False
    rules = list(POLICY_STMT_RE.finditer(src))

    for idx, m in enumerate(rules):
        effect = m.group("effect").lower()
        head = m.group("head") or ""
        actions = [a.upper() for a in POLICY_ACTION_RE.findall(head)]
        if actions and norm_action not in actions:
            continue
        p_m = POLICY_PRINCIPAL_RE.search(head)
        r_m = POLICY_RESOURCE_RE.search(head)
        if p_m or r_m:
            hierarchy_scope_checked = True
        p_ok = dag.is_member_of(
            eff_principal,
            p_m.group("target") if p_m else None,
            p_m.group("op").lower() if p_m else None,
        )
        res_ok = dag.is_member_of(
            eff_resource,
            r_m.group("target") if r_m else None,
            r_m.group("op").lower() if r_m else None,
        )
        if not (p_ok and res_ok):
            if effect == "permit":
                any_permit_scope_failed = True
            continue
        if effect == "permit":
            any_permit_scope_matched = True

        guard_kind = m.group("guard_kind").lower() if m.group("guard_kind") else None
        guard_expr = (m.group("guard_expr") or "").strip()
        try:
            guard_ast = PolicyGuardZ3Compiler.parse(guard_expr)
            guard_ok = bool(PolicyGuardZ3Compiler.eval_ast(guard_ast, eval_ctx))
            z_guard = PolicyGuardZ3Compiler.compile_z3(guard_ast, z3_ctx, z3_vars)
            if not z3.is_bool(z_guard):
                raise GuardCompileError("Guard must compile to BoolRef")
        except GuardCompileError:
            guard_ok = False
            z_guard = z3.BoolVal(False, ctx=z3_ctx)

        if guard_kind == "unless":
            applies = not guard_ok
            z_applies = z3.Not(z_guard)
        else:
            applies = guard_ok
            z_applies = z_guard

        rule_id = f"apodictic_policy_{idx + 1}_{effect}"
        if effect == "permit":
            matching_permit_z3.append(z_applies)
            if applies:
                permit_matched.append(rule_id)
        elif effect == "forbid":
            matching_forbid_z3.append(z_applies)
            if applies:
                forbid_triggered.append(rule_id)

    hierarchy_matched = any_permit_scope_matched or (not any_permit_scope_failed)
    z_forbid_none = (
        z3.And(*[z3.Not(zf) for zf in matching_forbid_z3])
        if matching_forbid_z3
        else z3.BoolVal(True, ctx=z3_ctx)
    )
    z_hier = z3.BoolVal((not hierarchy_scope_checked) or hierarchy_matched, ctx=z3_ctx)
    z_any_permit = (
        z3.Or(*matching_permit_z3)
        if matching_permit_z3
        else z3.BoolVal(False, ctx=z3_ctx)
    )

    s.assert_and_track(z_forbid_none, "POLICY_FORBID_OVERRIDE")
    s.assert_and_track(z_hier, "POLICY_ENTITY_HIERARCHY_MATCH")
    s.assert_and_track(z_any_permit, "POLICY_EXPLICIT_PERMIT_REQUIRED")

    chk = s.check()
    allowed = chk == z3.sat
    return {
        "engine": "apodictic-policy-z3-compiler-v3-symbolic-ast",
        "decision": "ALLOW" if allowed else "DENY",
        "verdict": "SAT" if allowed else "UNSAT",
        "allowed": allowed,
        "action": norm_action,
        "principal": eff_principal,
        "resource": eff_resource,
        "principal_ancestors": sorted(dag.ancestors(eff_principal)) if eff_principal else [],
        "resource_ancestors": sorted(dag.ancestors(eff_resource)) if eff_resource else [],
        "rules_evaluated": len(rules),
        "permit_matched": permit_matched,
        "forbid_triggered": forbid_triggered,
        "unsat_core": [] if allowed else [str(c) for c in s.unsat_core()],
        "smt_formula": s.to_smt2(),
    }


def strip_zero_width(text: str) -> str:
    return ZERO_WIDTH_RE.sub("", text or "")


def strip_sql_comments(sql: str) -> str:
    # Replace comments with space while respecting quoted strings cleanly
    parts: List[str] = []
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        if ch == "'":
            j = i + 1
            while j < n:
                if sql[j] == "'" and j + 1 < n and sql[j + 1] == "'":
                    j += 2
                elif sql[j] == "'":
                    j += 1
                    break
                else:
                    j += 1
            parts.append(sql[i:j])
            i = j
        elif sql[i : i + 2] == "--":
            j = sql.find("\n", i)
            i = n if j == -1 else j + 1
            parts.append(" ")
        elif sql[i : i + 2] == "/*":
            j = sql.find("*/", i + 2)
            i = n if j == -1 else j + 2
            parts.append(" ")
        else:
            parts.append(ch)
            i += 1
    return "".join(parts)


def split_sql_statements(sql: str) -> List[str]:
    clean = strip_sql_comments(strip_zero_width(sql))
    stmts: List[str] = []
    buf: List[str] = []
    in_single = False
    i = 0
    while i < len(clean):
        ch = clean[i]
        if ch == "'":
            in_single = not in_single
            buf.append(ch)
            if in_single and i + 1 < len(clean) and clean[i + 1] == "'":
                buf.append("'")
                i += 2
                in_single = not in_single
                continue
        elif ch == ";" and not in_single:
            piece = "".join(buf).strip()
            if piece:
                stmts.append(piece)
            buf = []
            i += 1
            continue
        else:
            buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        stmts.append(tail)
    return stmts


DOLLAR_BLOCK_RE = re.compile(r"\$([A-Za-z0-9_]*)\$([\s\S]*?)\$\1\$")
EXECUTE_STRING_RE = re.compile(r"\bEXECUTE\s+'((?:''|[^'])*)'", re.I)
CHR_CALL_RE = re.compile(r"\bCHR\s*\(\s*([0-9]{1,3})\s*\)", re.I)
HEX_DECODE_RE = re.compile(r"\bDECODE\s*\(\s*'([0-9A-Fa-f]+)'\s*,\s*'hex'\s*\)", re.I)
B64_DECODE_RE = re.compile(r"\bDECODE\s*\(\s*'([A-Za-z0-9+/=]+)'\s*,\s*'base64'\s*\)", re.I)
PARENTHESIZED_DML_DDL_RE = re.compile(
    r"\(\s*((?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER)\b[^()]+)\)",
    re.I,
)


def deobfuscate_dynamic_sql(sql_text: str) -> str:
    out = sql_text
    if CHR_CALL_RE.search(out):
        out = CHR_CALL_RE.sub(lambda m: f"'{chr(int(m.group(1)))}'" if 32 <= int(m.group(1)) <= 126 else " ", out)
    if HEX_DECODE_RE.search(out):
        def _hex(m: re.Match) -> str:
            try:
                return f"'{bytes.fromhex(m.group(1)).decode('utf-8', errors='ignore')}'"
            except Exception:
                return m.group(0)
        out = HEX_DECODE_RE.sub(_hex, out)
    if B64_DECODE_RE.search(out):
        def _b64(m: re.Match) -> str:
            try:
                return f"'{base64.b64decode(m.group(1)).decode('utf-8', errors='ignore')}'"
            except Exception:
                return m.group(0)
        out = B64_DECODE_RE.sub(_b64, out)
    prev = None
    while prev != out and "||" in out:
        prev = out
        out = re.sub(r"'([^']*)'\s*\|\|\s*'([^']*)'", r"'\1\2'", out)
    out = re.sub(r"\bCONVERT_FROM\s*\(\s*'([^']*)'\s*,\s*'[^']*'\s*\)", r"'\1'", out, flags=re.I)
    return out


def extract_procedural_and_cte_clauses(sql_text: str) -> Tuple[List[str], bool]:
    sql_text = deobfuscate_dynamic_sql(sql_text)
    extracted: List[str] = []
    upper = sql_text.upper()
    is_proc_ddl = bool(
        re.search(r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE|TRIGGER)\b", upper)
        or re.search(r"\bDO\s+(?:LANGUAGE\s+\w+\s+)?\$", upper)
    )
    for exec_m in EXECUTE_STRING_RE.finditer(DOLLAR_BLOCK_RE.sub(" ", sql_text)):
        dyn_sql = deobfuscate_dynamic_sql(exec_m.group(1).replace("''", "'"))
        if dyn_sql.strip():
            extracted.append(dyn_sql.strip())
    for m in DOLLAR_BLOCK_RE.finditer(sql_text):
        body = deobfuscate_dynamic_sql(m.group(2))
        for exec_m in EXECUTE_STRING_RE.finditer(body):
            dyn_sql = deobfuscate_dynamic_sql(exec_m.group(1).replace("''", "'"))
            if dyn_sql.strip():
                extracted.append(dyn_sql.strip())
        cleaned_body = re.sub(r"\b(?:DECLARE|BEGIN|END|EXCEPTION|RETURN\s+\w+)\b", " ; ", body, flags=re.I)
        for part in cleaned_body.split(";"):
            p = part.strip()
            if re.match(r"^(?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER)\b", p, re.I):
                extracted.append(p)
    scan_text = DOLLAR_BLOCK_RE.sub(" ", sql_text)
    for m in PARENTHESIZED_DML_DDL_RE.finditer(scan_text):
        sub = m.group(1).strip()
        if sub:
            extracted.append(sub)
    # Balanced-parenthesis scanner handles nested subqueries inside CTEs e.g. WITH x AS (DELETE ... WHERE id IN (SELECT 1))
    paren_stack: List[int] = []
    in_sq = False
    idx_p = 0
    while idx_p < len(scan_text):
        ch_p = scan_text[idx_p]
        if ch_p == "'":
            if in_sq and idx_p + 1 < len(scan_text) and scan_text[idx_p + 1] == "'":
                idx_p += 2
                continue
            in_sq = not in_sq
        elif not in_sq and ch_p == "(":
            paren_stack.append(idx_p)
        elif not in_sq and ch_p == ")" and paren_stack:
            s_idx = paren_stack.pop()
            inner_p = scan_text[s_idx + 1 : idx_p].strip()
            if re.match(r"^(?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|COPY|CALL|CREATE|GRANT|REVOKE)\b", inner_p, re.I):
                if inner_p not in extracted:
                    extracted.append(inner_p)
        idx_p += 1
    if re.match(r"^\s*WITH\b", scan_text, re.I):
        depth = 0
        last_close = -1
        for idx, ch in enumerate(scan_text):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
                if depth == 0:
                    tail_after = scan_text[idx + 1 :].lstrip()
                    if re.match(r"^(?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER)\b", tail_after, re.I):
                        last_close = idx
                        break
        if last_close != -1:
            main_tail = scan_text[last_close + 1 :].strip().rstrip(";").strip()
            if main_tail:
                extracted.append(main_tail)
    return extracted, is_proc_ddl


def _sg_eval_const(expr: Any) -> Optional[float]:
    if not HAS_SQLGLOT or expr is None:
        return None
    if isinstance(expr, sg_exp.Paren):
        return _sg_eval_const(expr.this)
    if isinstance(expr, sg_exp.Neg):
        v = _sg_eval_const(expr.this)
        return (-v) if v is not None else None
    if isinstance(expr, sg_exp.Literal) and expr.is_number:
        try:
            return float(expr.this)
        except Exception:
            return None
    if isinstance(expr, sg_exp.Add):
        l, r = _sg_eval_const(expr.left), _sg_eval_const(expr.right)
        return (l + r) if (l is not None and r is not None) else None
    if isinstance(expr, sg_exp.Sub):
        l, r = _sg_eval_const(expr.left), _sg_eval_const(expr.right)
        return (l - r) if (l is not None and r is not None) else None
    if isinstance(expr, sg_exp.Mul):
        l, r = _sg_eval_const(expr.left), _sg_eval_const(expr.right)
        return (l * r) if (l is not None and r is not None) else None
    if isinstance(expr, sg_exp.Div):
        l, r = _sg_eval_const(expr.left), _sg_eval_const(expr.right)
        return (l / r) if (l is not None and r is not None and r != 0.0) else None
    return None


def _sg_is_tautology_expr(expr: Any) -> bool:
    if not HAS_SQLGLOT or expr is None:
        return False
    if isinstance(expr, sg_exp.Paren):
        return _sg_is_tautology_expr(expr.this)
    if isinstance(expr, sg_exp.Boolean):
        return bool(expr.this)
    if isinstance(expr, sg_exp.Not) and isinstance(expr.this, sg_exp.Boolean):
        return not bool(expr.this.this)
    if isinstance(expr, sg_exp.Or):
        return _sg_is_tautology_expr(expr.left) or _sg_is_tautology_expr(expr.right)
    if isinstance(expr, sg_exp.And):
        return _sg_is_tautology_expr(expr.left) and _sg_is_tautology_expr(expr.right)
    if isinstance(expr, sg_exp.EQ):
        l_num, r_num = _sg_eval_const(expr.left), _sg_eval_const(expr.right)
        if l_num is not None and r_num is not None:
            return l_num == r_num
        if isinstance(expr.left, sg_exp.Literal) and isinstance(expr.right, sg_exp.Literal):
            return str(expr.left.this) == str(expr.right.this)
    return False


def analyze_sql_ast(sql: str) -> Dict[str, Any]:
    deobf = deobfuscate_dynamic_sql(sql)
    inner_clauses, is_proc_ddl = extract_procedural_and_cte_clauses(deobf)
    top_level_sql = DOLLAR_BLOCK_RE.sub(" ", deobf)
    stmts = split_sql_statements(top_level_sql)
    has_multi = len(stmts) > 1
    # Always preserve top-level statements alongside unwrapped subqueries/CTEs
    all_clauses = list(stmts)
    for c in inner_clauses:
        if c not in all_clauses:
            all_clauses.append(c)
    if not all_clauses:
        return {
            "statement_type": "ALTER" if is_proc_ddl else "QUERY",
            "target_tables": [],
            "has_where": False,
            "is_unbounded": is_proc_ddl,
            "multi_statement": has_multi,
            "statement_count": 1 if is_proc_ddl else 0,
            "ast_engine": "sqlglot-postgres" if HAS_SQLGLOT else "recursive-descent",
        }

    highest_op = "QUERY"
    tables: List[str] = []
    mutating_count = 0
    all_mutating_have_where = True
    any_unbounded = has_multi
    unparsed_clauses: List[str] = []

    if HAS_SQLGLOT:
        for clause in all_clauses:
            try:
                trees = [t for t in sqlglot.parse(clause, read="postgres", error_level=sqlglot.ErrorLevel.IGNORE) if t is not None]
            except Exception:
                trees = []
            if not trees:
                unparsed_clauses.append(clause)
                continue
            for tree in trees:
                for tbl in tree.find_all(sg_exp.Table):
                    tname = (tbl.name or "").lower()
                    if tname and tname not in tables:
                        tables.append(tname)
                for subnode in tree.walk():
                    op: Optional[str] = None
                    if isinstance(subnode, sg_exp.Drop):
                        op = "DROP"
                    elif isinstance(subnode, sg_exp.TruncateTable):
                        op = "TRUNCATE"
                    elif isinstance(subnode, sg_exp.Delete):
                        op = "DELETE"
                    elif isinstance(subnode, (sg_exp.Alter, sg_exp.Create)):
                        op = "ALTER"
                    elif isinstance(subnode, (sg_exp.Update, sg_exp.Merge)):
                        op = "UPDATE"
                    elif isinstance(subnode, sg_exp.Insert):
                        op = "INSERT"
                    elif isinstance(subnode, sg_exp.Select):
                        op = "QUERY"
                    elif isinstance(subnode, sg_exp.Command):
                        cmd_name = (subnode.this or "").upper().strip()
                        if cmd_name in ("DROP", "TRUNCATE", "ALTER"):
                            op = cmd_name
                        elif cmd_name == "COPY":
                            op = "INSERT"
                    if op is None:
                        continue
                    if SEVERITY_ORDER.get(op, 0) > SEVERITY_ORDER.get(highest_op, 0):
                        highest_op = op
                    if op in ("UPDATE", "DELETE"):
                        mutating_count += 1
                        wn = subnode.args.get("where")
                        if wn is None or _sg_is_tautology_expr(getattr(wn, "this", wn)):
                            all_mutating_have_where = False
                            any_unbounded = True
                    elif op in ("DROP", "TRUNCATE", "ALTER"):
                        mutating_count += 1
                        all_mutating_have_where = False
                        any_unbounded = True
    else:
        unparsed_clauses = list(all_clauses)

    for st in unparsed_clauses:
        upper = st.upper().strip()
        m_head = re.match(r"^([A-Z_]+)", upper)
        first_kw = m_head.group(1) if m_head else "UNKNOWN"
        if first_kw in ("SELECT", "EXPLAIN", "SHOW"):
            op = "QUERY"
        elif first_kw == "WITH":
            op = "UPDATE" if re.search(r"\b(?:DELETE|DROP|TRUNCATE|ALTER|UPDATE|INSERT|COPY)\b", upper) else "QUERY"
        elif first_kw == "INSERT":
            op = "UPDATE" if re.search(r"\bON\s+CONFLICT\b[\s\S]*\bDO\s+UPDATE\b", upper) else "INSERT"
        elif first_kw in ("UPDATE", "MERGE"):
            op = "UPDATE"
        elif first_kw in ("DELETE", "DROP", "TRUNCATE", "ALTER"):
            op = first_kw
        else:
            op = "ALTER"
            any_unbounded = True
            all_mutating_have_where = False
        if SEVERITY_ORDER.get(op, 5) >= SEVERITY_ORDER.get(highest_op, 0):
            highest_op = op

        tbl = ""
        m = re.search(r"^(?:UPDATE|INSERT\s+INTO|DELETE\s+FROM|DELETE|DROP\s+TABLE|TRUNCATE\s+TABLE|ALTER\s+TABLE|COPY)\s+([A-Za-z0-9_.\"`]+)", upper)
        if m:
            tbl = m.group(1).strip('"`').lower()
        else:
            m2 = re.search(r"\bFROM\s+([A-Za-z0-9_.\"`]+)", upper)
            if m2:
                tbl = m2.group(1).strip('"`').lower()
        if tbl and tbl not in tables:
            tables.append(tbl)

        has_where = bool(re.search(r"\bWHERE\b", upper))
        has_tautology = bool(
            re.search(
                r"\bWHERE\s+[\s\(]*(?:TRUE|1\s*=\s*1|2\s*=\s*2|2\s*>\s*1|1\s*<\s*2|0\s*=\s*0|'[^']+'\s*=\s*'[^']+')\b"
                r"|\bOR\s+[\s\(]*(?:TRUE|1\s*=\s*1|2\s*=\s*2|2\s*>\s*1)\b"
                r"|\bWHERE\s+([A-Z_][A-Z0-9_]*)\s*=\s*\1\b"
                r"|\bWHERE\s+[A-Z0-9_.]+\s+IS\s+NOT\s+NULL\s*(?:;|$)",
                upper,
            )
        )
        if op in ("UPDATE", "DELETE"):
            mutating_count += 1
            if not has_where or has_tautology:
                all_mutating_have_where = False
                any_unbounded = True
        elif op in ("DROP", "TRUNCATE", "ALTER"):
            mutating_count += 1
            all_mutating_have_where = False
            any_unbounded = True

    if is_proc_ddl and SEVERITY_ORDER.get(highest_op, 0) < SEVERITY_ORDER.get("UPDATE", 3):
        highest_op = "ALTER"

    if is_proc_ddl and highest_op in ("DROP", "TRUNCATE", "DELETE", "ALTER"):
        any_unbounded = True

    return {
        "statement_type": highest_op,
        "target_tables": tables,
        "has_where": all_mutating_have_where if mutating_count > 0 and highest_op in ("UPDATE", "DELETE") else False,
        "is_unbounded": any_unbounded,
        "multi_statement": has_multi,
        "statement_count": len(all_clauses),
        "ast_engine": "sqlglot-postgres" if HAS_SQLGLOT else "recursive-descent",
    }


def extract_sql_amount(sql: str, current_balance: float = 0.0) -> float:
    deobf = deobfuscate_dynamic_sql(strip_sql_comments(strip_zero_width(sql)))
    inner_clauses, _ = extract_procedural_and_cte_clauses(deobf)
    top_stmts = split_sql_statements(DOLLAR_BLOCK_RE.sub(" ", deobf))
    clauses = list(top_stmts)
    for cl in inner_clauses:
        if cl not in clauses:
            clauses.append(cl)

    ast_total = 0.0
    zeroed_bal = False
    debit_cols = {"balance", "cash", "reserve", "available", "funds", "credit", "equity"}
    amt_cols = {"amount", "amt", "total", "total_amount", "payment_amount", "payout", "disbursement", "transfer_amount", "debit", "wire_amount", "refund_amount"}
    if HAS_SQLGLOT:
        def _extract_rhs_debit(expr: Any, col: str) -> Optional[float]:
            cv = _sg_eval_const(expr)
            if cv is not None:
                if cv <= 0:
                    return float(current_balance) if current_balance > 0 else 1e9
                if 0 < current_balance and cv < current_balance:
                    return float(current_balance) - cv
                return 0.0
            # Collect subtracted or negative-added constants on the same column: balance - 45000 - 45000 or balance + (-90000)
            def _sum_drains(node: Any) -> Tuple[bool, float]:
                if isinstance(node, sg_exp.Column):
                    return node.name.lower().split(".")[-1] == col, 0.0
                if isinstance(node, sg_exp.Paren):
                    return _sum_drains(node.this)
                if isinstance(node, sg_exp.Sub):
                    has_c, l_drain = _sum_drains(node.left)
                    r_val = _sg_eval_const(node.right)
                    if has_c and r_val is not None:
                        return True, l_drain + r_val
                    return has_c, l_drain
                if isinstance(node, sg_exp.Add):
                    has_c, l_drain = _sum_drains(node.left)
                    r_val = _sg_eval_const(node.right)
                    if has_c and r_val is not None:
                        return True, l_drain - r_val
                    has_r, r_drain = _sum_drains(node.right)
                    l_val = _sg_eval_const(node.left)
                    if has_r and l_val is not None:
                        return True, r_drain - l_val
                    return False, 0.0
                return False, 0.0
            has_col, drain = _sum_drains(expr)
            if has_col and drain > 0:
                return drain
            if isinstance(expr, (sg_exp.Case, sg_exp.Subquery)):
                return float(current_balance) if current_balance > 0 else 1e9
            return None

        for cl in clauses:
            try:
                trees = sqlglot.parse(cl, read="postgres", error_level=sqlglot.ErrorLevel.IGNORE)
            except Exception:
                trees = []
            for tree in trees:
                if tree is None:
                    continue
                for upd in tree.find_all(sg_exp.Update):
                    for eq in upd.expressions:
                        if not isinstance(eq, sg_exp.EQ) or eq.left is None or eq.right is None:
                            continue
                        col = (eq.left.name if hasattr(eq.left, "name") else eq.left.sql()).lower().split(".")[-1]
                        if col in debit_cols:
                            dr = _extract_rhs_debit(eq.right, col)
                            if dr is not None and dr > 0:
                                ast_total += dr
                            elif dr is None:
                                zeroed_bal = True
                        elif col in amt_cols:
                            v = _sg_eval_const(eq.right)
                            if v is not None and v > 0:
                                ast_total += v
                for ins in tree.find_all(sg_exp.Insert):
                    col_nodes = ins.this.expressions if isinstance(ins.this, sg_exp.Schema) else []
                    col_names = [c.name.lower().split(".")[-1] for c in col_nodes if hasattr(c, "name")]
                    values_node = ins.args.get("expression")
                    if isinstance(values_node, sg_exp.Values):
                        for tup in values_node.expressions:
                            exprs = list(getattr(tup, "expressions", []) or [])
                            matched = False
                            if col_names and len(col_names) == len(exprs):
                                for cname, val_expr in zip(col_names, exprs):
                                    if cname in amt_cols:
                                        v = _sg_eval_const(val_expr)
                                        if v is not None and v > 0:
                                            ast_total += v
                                            matched = True
                            if not matched:
                                nums = [_sg_eval_const(e) for e in exprs]
                                pos_nums = [x for x in nums if x is not None and x > 0]
                                tbl_str = str(ins.this).lower()
                                if pos_nums and any(k in tbl_str for k in ("transfer", "payout", "payment", "wire", "disburse", "ledger", "invoice", "journal", "move", "refund", "charge", "account", "vendor")):
                                    ast_total += max(pos_nums)

    if zeroed_bal:
        return max(ast_total, float(current_balance) if current_balance > 0 else 1e9)

    clean = deobf
    dollar_inner = " ; ".join(m.group(2) for m in DOLLAR_BLOCK_RE.finditer(clean))
    exec_inner = " ; ".join(m.group(1).replace("''", "'") for m in EXECUTE_STRING_RE.finditer(clean))
    without_dollars = DOLLAR_BLOCK_RE.sub(" ", clean)
    scrubbed_main = STRING_LIT_RE.sub(" '' ", without_dollars)
    scrubbed_dollar = STRING_LIT_RE.sub(" '' ", dollar_inner)
    scrubbed = f"{scrubbed_main} ; {scrubbed_dollar} ; {exec_inner}"

    cands: List[float] = []
    for bal_m in re.finditer(
        r"\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:balance|cash|reserve|available|funds|credit|equity)\s*=\s*([^\n,;]+?)(?=\bWHERE\b|\bRETURNING\b|$)",
        scrubbed,
        re.I,
    ):
        rhs = bal_m.group(1).strip()
        if re.match(r"^(?:[A-Za-z_][A-Za-z0-9_.]*)\s*[-+]", rhs, re.I):
            for sub_m in re.finditer(r"(?:-\s*|\+\s*\(\s*-\s*)([0-9]+(?:\.[0-9]+)?)", rhs):
                cands.append(float(sub_m.group(1)))
        elif re.match(r"^[0-9]+(?:\.[0-9]+)?$", rhs):
            lit_target = float(rhs)
            if lit_target <= 0:
                cands.append(float(current_balance) if current_balance > 0 else 1e9)
            elif current_balance > 0 and lit_target < current_balance:
                cands.append(float(current_balance) - lit_target)
    for m in re.finditer(
        r"\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:amount|amt|total|total_amount|payment_amount|payout|disbursement|transfer_amount|debit|wire_amount|refund_amount)\s*=\s*([0-9]+(?:\.[0-9]+)?)",
        scrubbed,
        re.I,
    ):
        cands.append(float(m.group(1)))
    for ins_m in re.finditer(
        r"\bINSERT\s+INTO\s+[A-Za-z0-9_.]*(?:transfer|payout|payment|wire|disburse|ledger|invoice|journal|move|refund|charge|account|vendor)[A-Za-z0-9_.]*(?:\s*\(([^)]*)\))?\s*\bVALUES\s*\(([^)]+)\)",
        scrubbed,
        re.I,
    ):
        cols = [c.strip().strip('"`').lower() for c in ins_m.group(1).split(",")] if ins_m.group(1) else []
        vals = [v.strip() for v in ins_m.group(2).split(",")]
        matched_named = False
        if cols and len(cols) == len(vals):
            for cn, vn in zip(cols, vals):
                if cn in amt_cols and re.match(r"^[0-9]+(?:\.[0-9]+)?$", vn):
                    cands.append(float(vn))
                    matched_named = True
        if not matched_named:
            nums = [float(x) for x in re.findall(r"(?<![A-Za-z_])([0-9]+(?:\.[0-9]+)?)", ins_m.group(2))]
            if nums:
                cands.append(max(nums))
    regex_total = sum(cands) if cands else 0.0
    return max(ast_total, regex_total)


def detect_negative_sql_literal(sql: Optional[str]) -> Optional[float]:
    if not sql or not isinstance(sql, str):
        return None
    clean = deobfuscate_dynamic_sql(strip_comments(sql))
    dollar_inner = " ; ".join(m.group(2) for m in DOLLAR_BLOCK_RE.finditer(clean))
    exec_inner = " ; ".join(m.group(1).replace("''", "'") for m in EXECUTE_STRING_RE.finditer(clean))
    without_dollars = DOLLAR_BLOCK_RE.sub(" ", clean)
    scrubbed_main = STRING_LIT_RE.sub(" '' ", without_dollars)
    scrubbed_dollar = STRING_LIT_RE.sub(" '' ", dollar_inner)
    scrubbed = f"{scrubbed_main} ; {scrubbed_dollar} ; {exec_inner}"

    amt_cols = {"amount", "amt", "total", "total_amount", "payment_amount", "payout", "disbursement", "transfer_amount", "debit", "wire_amount", "refund_amount"}
    worst_neg: Optional[float] = None

    for m in re.finditer(
        r"\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:amount|amt|total|total_amount|payment_amount|payout|disbursement|transfer_amount|debit|wire_amount|refund_amount)\s*=\s*(-\s*[0-9]+(?:\.[0-9]+)?)",
        scrubbed,
        re.I,
    ):
        val = -abs(float(m.group(1).replace(" ", "")))
        worst_neg = val if worst_neg is None else min(worst_neg, val)

    for ins_m in re.finditer(
        r"\bINSERT\s+INTO\s+([A-Za-z0-9_.\"`]+)(?:\s*\(([^)]*)\))?\s*\bVALUES\s*\(([^)]+)\)",
        scrubbed,
        re.I,
    ):
        tbl = ins_m.group(1).lower()
        cols = [c.strip().strip('"`').lower() for c in ins_m.group(2).split(",")] if ins_m.group(2) else []
        vals = [v.strip() for v in ins_m.group(3).split(",")]
        matched_named = False
        if cols and len(cols) == len(vals):
            for cn, vn in zip(cols, vals):
                if cn in amt_cols and re.match(r"^-\s*[0-9]+(?:\.[0-9]+)?$", vn):
                    val = -abs(float(vn.replace(" ", "")))
                    worst_neg = val if worst_neg is None else min(worst_neg, val)
                    matched_named = True
        if not matched_named and any(k in tbl for k in ("transfer", "payout", "payment", "wire", "disburse", "ledger", "invoice", "journal", "move", "refund", "charge", "account", "vendor")):
            for vn in vals:
                if re.match(r"^-\s*[0-9]+(?:\.[0-9]+)?$", vn):
                    val = -abs(float(vn.replace(" ", "")))
                    worst_neg = val if worst_neg is None else min(worst_neg, val)
    return worst_neg


def _format_safe_amount(val: float) -> str:
    rounded = round(max(0.0, float(val)), 2)
    if abs(rounded - round(rounded)) < 1e-9:
        return str(int(round(rounded)))
    return f"{rounded:.2f}".rstrip("0").rstrip(".")


def synthesize_patched_sql(sql: Optional[str], max_safe_amount: float) -> Optional[str]:
    if not sql or not isinstance(sql, str):
        return None
    if re.match(r"^\s*(?:DROP|TRUNCATE|ALTER)\b", sql.upper()):
        return None
    safe_str = _format_safe_amount(max_safe_amount)
    candidates: List[Tuple[float, int, int]] = []
    for pat in (
        r"\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:balance|cash|reserve|available|funds|credit|equity)\s*=\s*(?:[A-Za-z_][A-Za-z0-9_.]*\s*)?-\s*(-?\s*[0-9]+(?:\.[0-9]+)?)",
        r"\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:amount|amt|total|total_amount|payment_amount|payout|disbursement|transfer_amount|debit|wire_amount|refund_amount)\s*=\s*(-?\s*[0-9]+(?:\.[0-9]+)?)",
    ):
        for m in re.finditer(pat, sql, re.I):
            candidates.append((float(m.group(1).replace(" ", "")), m.start(1), m.end(1)))
    if not candidates:
        for ins_m in re.finditer(r"\bVALUES\s*\(([^)]+)\)", sql, re.I):
            base = ins_m.start(1)
            for num_m in re.finditer(r"(?<![A-Za-z0-9_.])(-?\s*[0-9]+(?:\.[0-9]+)?)", ins_m.group(1)):
                if ins_m.group(1)[: num_m.start(1)].count("'") % 2 == 1:
                    continue
                candidates.append((float(num_m.group(1).replace(" ", "")), base + num_m.start(1), base + num_m.end(1)))
    if not candidates:
        for num_m in re.finditer(r"(?<![A-Za-z0-9_.])(-?\s*[0-9]+(?:\.[0-9]+)?)", sql):
            prefix = sql[: num_m.start(1)]
            if prefix.count("'") % 2 == 1:
                continue
            if re.search(r"\b(?:id|account_id)\s*=\s*$", prefix, re.I):
                continue
            candidates.append((float(num_m.group(1).replace(" ", "")), num_m.start(1), num_m.end(1)))
    if not candidates:
        return None
    if max_safe_amount <= 0.0:
        neg_cands = [item for item in candidates if item[0] < 0]
        if neg_cands:
            _, start, end = min(neg_cands, key=lambda item: item[0])
            return sql[:start] + safe_str + sql[end:]
    _, start, end = max(candidates, key=lambda item: abs(item[0]))
    return sql[:start] + safe_str + sql[end:]


def compute_counterfactual_patch(
    initial_balance: float,
    minimum_reserve: float,
    spending_limit: float,
    cfo_signed: bool,
    total_spend: float,
    sql: Optional[str] = None,
) -> Dict[str, Any]:
    opt_ctx = z3.Context()
    opt = z3.Optimize(ctx=opt_ctx)
    opt.set("timeout", 5000)
    safe_amt = z3.Real("safe_amt", ctx=opt_ctx)
    is_neg = float(total_spend) < 0.0
    opt.add(safe_amt >= 0)
    if is_neg:
        opt.add(safe_amt == 0)
    else:
        opt.add(z3.RealVal(str(initial_balance), ctx=opt_ctx) - safe_amt >= z3.RealVal(str(minimum_reserve), ctx=opt_ctx))
        if not cfo_signed:
            opt.add(safe_amt <= z3.RealVal(str(spending_limit), ctx=opt_ctx))
    opt.maximize(safe_amt)

    max_safe_amount = 0.0
    if opt.check() == z3.sat:
        val = opt.model().eval(safe_amt, model_completion=True)
        try:
            if hasattr(val, "as_fraction"):
                max_safe_amount = float(val.as_fraction())
            else:
                max_safe_amount = float(val.as_decimal(6).rstrip("?"))
        except Exception:
            max_safe_amount = 0.0
    max_safe_amount = 0.0 if is_neg else round(max(0.0, max_safe_amount), 2)
    reduction_delta = round(abs(float(total_spend)), 2) if is_neg else round(max(0.0, float(total_spend) - max_safe_amount), 2)
    patched_sql = synthesize_patched_sql(sql, max_safe_amount)
    return {
        "max_safe_amount": max_safe_amount,
        "reduction_delta": reduction_delta,
        "patched_sql": patched_sql,
        "solver": "z3.Optimize",
    }


def scrub_text_detailed(raw: str) -> Tuple[str, int, Dict[str, Any]]:
    text = strip_zero_width(raw)
    count = 0
    seen: Dict[str, str] = {}
    counters: Dict[str, int] = {}
    iban_mod97_valid = 0
    luhn_pan_valid = 0

    def _sub(prefix: str, val: str) -> str:
        nonlocal count, iban_mod97_valid, luhn_pan_valid
        if prefix == "CARD" and not validate_luhn_pan(val):
            return val
        if prefix == "IBAN" and validate_iban_mod97(val):
            iban_mod97_valid += 1
        elif prefix == "CARD":
            luhn_pan_valid += 1
        if val in seen:
            return seen[val]
        counters[prefix] = counters.get(prefix, 0) + 1
        tok = f"<SYM_{prefix}_{counters[prefix]:02d}>"
        seen[val] = tok
        count += 1
        return tok

    for prefix, regex in PII_RULES:
        text = regex.sub(lambda m, p=prefix: _sub(p, m.group(0)), text)
    return text, count, {
        "iban_mod97_valid_count": iban_mod97_valid,
        "luhn_pan_valid_count": luhn_pan_valid,
        "validators": ["ISO-7064-Mod-97-10", "Luhn-Mod-10"],
    }


def scrub_text(raw: str) -> Tuple[str, int]:
    text, count, _ = scrub_text_detailed(raw)
    return text, count


class StandaloneEnclaveSession:
    def __init__(self, state_db_path: str = ""):
        self.started_at = time.perf_counter()
        self.state_db_path = state_db_path or os.environ.get("APODICTIC_STATE_DB") or os.path.join(
            os.path.expanduser("~"), ".apodictic", "enclave_state.db"
        )
        os.makedirs(os.path.dirname(self.state_db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.state_db_path, check_same_thread=False, timeout=5.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA busy_timeout=5000;")
        self._init_schema()
        self.conn.execute(
            "INSERT OR IGNORE INTO ledger_accounts (account_id, balance, min_reserve, debits_pending, debits_posted, credits_posted) VALUES (?, ?, ?, 0.0, 0.0, ?)",
            ("sdk_default", 250000.0, 50000.0, 250000.0),
        )
        self.conn.execute(
            "UPDATE ledger_accounts SET credits_posted = balance WHERE account_id = ? AND credits_posted = 0.0 AND debits_pending = 0.0 AND debits_posted = 0.0",
            ("sdk_default",),
        )
        self.conn.commit()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS velocity_events (
                account_id TEXT NOT NULL,
                amount REAL NOT NULL,
                ts REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS worm_blocks (
                block_index INTEGER PRIMARY KEY,
                block_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ledger_accounts (
                account_id TEXT PRIMARY KEY,
                balance REAL NOT NULL,
                min_reserve REAL NOT NULL DEFAULT 0.0,
                debits_pending REAL NOT NULL DEFAULT 0.0,
                debits_posted REAL NOT NULL DEFAULT 0.0,
                credits_posted REAL NOT NULL DEFAULT 0.0
            );
            CREATE TABLE IF NOT EXISTS wal_tuple_journal (
                tuple_id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL,
                lsn TEXT NOT NULL,
                table_name TEXT NOT NULL,
                before_image_json TEXT NOT NULL,
                after_image_json TEXT NOT NULL,
                restored INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rollback_batches (
                batch_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                amount REAL NOT NULL,
                target_system TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                rolled_back_at REAL
            );
            CREATE TABLE IF NOT EXISTS bitemporal_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_id TEXT NOT NULL,
                data_json TEXT NOT NULL,
                valid_start INTEGER NOT NULL,
                valid_end INTEGER NOT NULL,
                system_start INTEGER NOT NULL,
                system_end INTEGER NOT NULL
            );
            """
        )
        for col in ("debits_pending", "debits_posted", "credits_posted"):
            try:
                self.conn.execute(f"ALTER TABLE ledger_accounts ADD COLUMN {col} REAL NOT NULL DEFAULT 0.0")
            except sqlite3.OperationalError:
                pass
        self.conn.execute(
            "UPDATE ledger_accounts SET credits_posted = balance WHERE credits_posted = 0.0 AND debits_pending = 0.0 AND debits_posted = 0.0 AND balance > 0.0"
        )
        self.conn.commit()

    def _get_double_entry_account(self, account_id: str) -> Dict[str, Any]:
        row = self.conn.execute("SELECT * FROM ledger_accounts WHERE account_id = ?", (account_id,)).fetchone()
        if not row:
            return {
                "account_id": account_id,
                "balance": 0.0,
                "min_reserve": 0.0,
                "debits_pending": 0.0,
                "debits_posted": 0.0,
                "credits_posted": 0.0,
                "available_balance": 0.0,
            }
        credits_posted = float(row["credits_posted"])
        debits_posted = float(row["debits_posted"])
        debits_pending = float(row["debits_pending"])
        return {
            "account_id": row["account_id"],
            "balance": round(float(row["balance"]), 4),
            "min_reserve": round(float(row["min_reserve"]), 4),
            "debits_pending": round(debits_pending, 4),
            "debits_posted": round(debits_posted, 4),
            "credits_posted": round(credits_posted, 4),
            "available_balance": round(credits_posted - debits_posted - debits_pending, 4),
        }

    def _all_blocks(self) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT block_json FROM worm_blocks ORDER BY block_index ASC").fetchall()
        return [json.loads(r["block_json"]) for r in rows]

    def _append_block(self, proof_id: str, action: str, verdict: str, target_system: str, zk_digest: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        last_row = self.conn.execute("SELECT block_index, block_json FROM worm_blocks ORDER BY block_index DESC LIMIT 1").fetchone()
        prev_blk = json.loads(last_row["block_json"]) if last_row else None
        prev_hash = prev_blk["block_hash"] if prev_blk else GENESIS_HASH
        idx = int(prev_blk["block_index"]) + 1 if prev_blk else 1
        payload: Dict[str, Any] = {
            "block_index": idx,
            "previous_hash": prev_hash,
            "timestamp_ns": time.time_ns(),
            "proof_id": proof_id,
            "action": action,
            "verdict": verdict,
            "target_system": target_system,
            "zk_digest": zk_digest,
            "metadata": metadata,
        }
        serialized = json.dumps(payload, sort_keys=True)
        block_hash = hashlib.sha256(f"{prev_hash}:{serialized}".encode("utf-8")).hexdigest()
        payload["block_hash"] = block_hash
        rows = self.conn.execute("SELECT block_json FROM worm_blocks ORDER BY block_index ASC").fetchall()
        leaves = [rfc6962_leaf_hash(str(json.loads(r["block_json"])["block_hash"]).encode("utf-8")) for r in rows]
        new_leaf = rfc6962_leaf_hash(block_hash.encode("utf-8"))
        leaves.append(new_leaf)
        payload["rfc6962_leaf_hash"] = new_leaf.hex()
        payload["rfc6962_tree_root"] = rfc6962_tree_hash(leaves).hex()
        self.conn.execute(
            "INSERT INTO worm_blocks (block_index, block_json) VALUES (?, ?)",
            (idx, json.dumps(payload, sort_keys=True)),
        )
        self.conn.commit()
        return payload

    def generate_rfc6962_inclusion_proof(self, block_index: Optional[int] = None) -> Dict[str, Any]:
        blocks = self._all_blocks()
        if not blocks:
            return {
                "spec": "RFC-6962-Certificate-Transparency-v1",
                "block_index": 0,
                "leaf_index": 0,
                "tree_size": 0,
                "leaf_hash": None,
                "root_hash": hashlib.sha256(b"").hexdigest(),
                "audit_path": [],
                "inclusion_verified": False,
            }
        target_idx = int(block_index) if block_index else len(blocks)
        idx = target_idx - 1
        if idx < 0 or idx >= len(blocks):
            raise ValueError(f"Block index {target_idx} out of bounds (1..{len(blocks)})")
        leaves = [rfc6962_leaf_hash(str(b["block_hash"]).encode("utf-8")) for b in blocks]
        leaf = leaves[idx]
        path = rfc6962_audit_path(idx, leaves)
        root = rfc6962_tree_hash(leaves)
        verified = rfc6962_verify_inclusion(leaf, idx, len(leaves), path, root)
        return {
            "spec": "RFC-6962-Certificate-Transparency-v1",
            "block_index": target_idx,
            "leaf_index": idx,
            "tree_size": len(leaves),
            "leaf_hash": leaf.hex(),
            "root_hash": root.hex(),
            "audit_path": [p.hex() for p in path],
            "inclusion_verified": verified,
        }

    def _verify_chain(self) -> Tuple[bool, int, str]:
        blocks = self._all_blocks()
        prev = GENESIS_HASH
        for blk in blocks:
            if blk.get("previous_hash") != prev:
                return False, len(blocks), blocks[-1].get("block_hash", GENESIS_HASH)
            copy = dict(blk)
            actual = copy.pop("block_hash", "")
            copy.pop("rfc6962_leaf_hash", None)
            copy.pop("rfc6962_tree_root", None)
            serialized = json.dumps(copy, sort_keys=True)
            recalc = hashlib.sha256(f"{prev}:{serialized}".encode("utf-8")).hexdigest()
            if recalc != actual:
                return False, len(blocks), blocks[-1].get("block_hash", GENESIS_HASH)
            prev = actual
        return True, len(blocks), prev

    def handle(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if method == "health":
            valid, cnt, tip = self._verify_chain()
            accts = self.conn.execute("SELECT COUNT(DISTINCT account_id) FROM velocity_events").fetchone()[0]
            bt_cnt = self.conn.execute("SELECT COUNT(*) FROM bitemporal_records").fetchone()[0]
            return {
                "status": "healthy",
                "mode": "standalone-enclave",
                "z3_version": z3.get_version_string(),
                "uptime_ms": round((time.perf_counter() - self.started_at) * 1000.0, 2),
                "worm_blocks": cnt,
                "worm_integrity_valid": valid,
                "tip_hash": tip,
                "velocity_accounts": accts,
                "bitemporal_records": bt_cnt,
            }

        if method == "verify_mutation":
            t0 = time.perf_counter()
            raw_sql = str(params.get("sql", ""))
            acct = str(params.get("accountId", "sdk_default"))
            has_explicit_bal = bool(params.get("hasExplicitCurrentBalance", "currentBalance" in params and params.get("currentBalance") is not None))
            existing_acct_row = self.conn.execute(
                "SELECT balance, min_reserve FROM ledger_accounts WHERE account_id = ?",
                (acct,),
            ).fetchone()
            use_persisted_bal = existing_acct_row is not None and not has_explicit_bal and not bool(params.get("stateless", False))
            curr_bal = float(existing_acct_row["balance"]) if use_persisted_bal else float(params.get("currentBalance", 250000.0))
            min_res = float(existing_acct_row["min_reserve"]) if use_persisted_bal else float(params.get("minReserve", 50000.0))
            spend_cap = float(params.get("maxAutonomousLimit", 50000.0))
            cfo_signed = bool(params.get("cfoSigned", False))
            vat_rate = float(params.get("statutoryVat", 0.14))
            exp_vat = float(params.get("expectedVat", 0.14))
            extracted_amt = extract_sql_amount(raw_sql, current_balance=curr_bal)
            neg_sql_amt = detect_negative_sql_literal(raw_sql)
            amt_raw = params.get("amount")
            caller_amt = float(amt_raw) if amt_raw is not None else 0.0
            if caller_amt < 0 or caller_amt != caller_amt or math.isinf(caller_amt):
                raise ValueError("Invalid negative, NaN, or infinite amount")

            prior_sum = float(
                self.conn.execute(
                    "SELECT COALESCE(SUM(amount), 0.0) FROM velocity_events WHERE account_id = ? AND ts >= ?",
                    (acct, time.time() - 86400.0),
                ).fetchone()[0]
            )
            if neg_sql_amt is not None and caller_amt == 0.0:
                amt_val = neg_sql_amt
                effective_amt = neg_sql_amt
            else:
                amt_val = max(caller_amt, extracted_amt)
                if amt_val < 0 or amt_val != amt_val:
                    raise ValueError("Invalid negative or NaN amount")
                effective_amt = amt_val + prior_sum

            sanitized_sql, redactions, dlp_checksums = scrub_text_detailed(raw_sql)
            dlp_ms = (time.perf_counter() - t0) * 1000.0

            ast_t0 = time.perf_counter()
            ast = analyze_sql_ast(raw_sql)
            ast_ms = (time.perf_counter() - ast_t0) * 1000.0

            has_multi = bool(ast["multi_statement"])
            is_destructive = has_multi or ast["is_unbounded"] or ast["statement_type"] in ("DELETE", "DROP", "TRUNCATE", "ALTER")
            rev_armed = False if has_multi else (not is_destructive)

            z0 = time.perf_counter()
            ctx = z3.Context()
            s = z3.Solver(ctx=ctx)
            s.set("timeout", 5000)

            z_bal = z3.Real("initial_balance", ctx=ctx)
            z_min = z3.Real("min_reserve", ctx=ctx)
            z_cap = z3.Real("spending_limit", ctx=ctx)
            z_cfo = z3.Bool("cfo_signed", ctx=ctx)
            z_dest = z3.Bool("is_destructive", ctx=ctx)
            z_arm = z3.Bool("reversal_armed", ctx=ctx)
            z_vat = z3.Real("vat_rate", ctx=ctx)
            z_evat = z3.Real("expected_vat", ctx=ctx)
            z_amt = z3.Real("tx_effective_amt", ctx=ctx)

            s.add(z_bal == z3.RealVal(str(curr_bal), ctx=ctx))
            s.add(z_min == z3.RealVal(str(min_res), ctx=ctx))
            s.add(z_cap == z3.RealVal(str(spend_cap), ctx=ctx))
            s.add(z_cfo == z3.BoolVal(cfo_signed, ctx=ctx))
            s.add(z_dest == z3.BoolVal(is_destructive, ctx=ctx))
            s.add(z_arm == z3.BoolVal(rev_armed, ctx=ctx))
            s.add(z_vat == z3.RealVal(str(vat_rate), ctx=ctx))
            s.add(z_evat == z3.RealVal(str(exp_vat), ctx=ctx))
            s.add(z_amt == z3.RealVal(str(effective_amt), ctx=ctx))

            s.assert_and_track(z3.Or(z3.Not(z_dest), z_arm), "INV_REVERSIBILITY_GUARD")
            s.assert_and_track(z_vat == z_evat, "INV_STATUTORY_TAX_PARITY")
            s.assert_and_track(z_amt >= 0, "INV_NON_NEGATIVE")
            s.assert_and_track(z3.Or(z_amt <= z_cap, z_cfo), "INV_SPEND_CAP")
            s.assert_and_track(z_bal - z_amt >= z_min, "INV_SOLVENCY_FLOOR")

            debit_total_raw = params.get("debitTotal")
            credit_total_raw = params.get("creditTotal")
            double_entry_detail: Optional[str] = None
            if debit_total_raw is not None and credit_total_raw is not None:
                debit_total = float(debit_total_raw)
                credit_total = float(credit_total_raw)
                z_debit = z3.Real("debit_total", ctx=ctx)
                z_credit = z3.Real("credit_total", ctx=ctx)
                z_tol = z3.RealVal("0.005", ctx=ctx)
                s.add(z_debit == z3.RealVal(str(debit_total), ctx=ctx))
                s.add(z_credit == z3.RealVal(str(credit_total), ctx=ctx))
                s.assert_and_track(
                    z3.And(z_debit - z_credit <= z_tol, z_credit - z_debit <= z_tol),
                    "INV_DOUBLE_ENTRY_BALANCE",
                )
                if abs(debit_total - credit_total) > 0.005:
                    double_entry_detail = (
                        f"INV_DOUBLE_ENTRY_BALANCE: sum(debit)={debit_total:.2f} != "
                        f"sum(credit)={credit_total:.2f} (drift=${abs(debit_total - credit_total):.2f})"
                    )

            chk = s.check()
            z3_ms = (time.perf_counter() - z0) * 1000.0
            verified = chk == z3.sat
            verdict = "SAT" if verified else "UNSAT"
            core = [] if verified else [str(c) for c in s.unsat_core()]
            if has_multi and "MULTI_STATEMENT_SQL_BLOCKED" not in core:
                core.insert(0, "MULTI_STATEMENT_SQL_BLOCKED")
            violation_reason = (
                double_entry_detail
                if (not verified and "INV_DOUBLE_ENTRY_BALANCE" in core and double_entry_detail)
                else (core[0] if core else None)
            )
            counterfactual_patch = (
                None
                if verified
                else compute_counterfactual_patch(
                    initial_balance=curr_bal,
                    minimum_reserve=min_res,
                    spending_limit=spend_cap,
                    cfo_signed=cfo_signed,
                    total_spend=effective_amt,
                    sql=raw_sql,
                )
            )

            proof_id = f"prf_{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
            digest = hashlib.sha256(f"{proof_id}:{verdict}:{curr_bal}:{effective_amt}:{sanitized_sql}".encode()).hexdigest()

            if verified and amt_val > 0:
                self.conn.execute(
                    "INSERT INTO velocity_events (account_id, amount, ts) VALUES (?, ?, ?)",
                    (acct, amt_val, time.time()),
                )

            blk = self._append_block(
                proof_id=proof_id,
                action=ast["statement_type"],
                verdict=verdict,
                target_system=str(params.get("targetSystem", "POSTGRESQL")).upper(),
                zk_digest=digest,
                metadata={"tables": ast["target_tables"], "unbounded": ast["is_unbounded"], "multi_statement": has_multi},
            )

            target_sys_raw = str(params.get("targetSystem", "postgresql")).lower()
            is_ext_escrow = any(k in target_sys_raw for k in ("stripe", "wire", "iso20022", "netsuite")) or any(
                k in raw_sql.upper() for k in ("WIRE", "PAYOUT", "STRIPE", "ISO20022")
            )
            escrow_status = ("ESCROW_HELD" if is_ext_escrow else "SAVEPOINT_STAGED") if verified else "VETOED_PRE_COMMIT"
            batch_id = None
            wal_before_image: Optional[Dict[str, Any]] = None
            if verified:
                self.conn.execute(
                    "INSERT OR IGNORE INTO ledger_accounts (account_id, balance, min_reserve, debits_pending, debits_posted, credits_posted) VALUES (?, ?, ?, 0.0, 0.0, ?)",
                    (acct, curr_bal, min_res, curr_bal),
                )
                wal_before_image = self._get_double_entry_account(acct)
                if is_ext_escrow:
                    self.conn.execute(
                        "UPDATE ledger_accounts SET balance = balance - ?, debits_pending = debits_pending + ? WHERE account_id = ?",
                        (amt_val, amt_val, acct),
                    )
                else:
                    self.conn.execute(
                        "UPDATE ledger_accounts SET balance = balance - ?, debits_posted = debits_posted + ? WHERE account_id = ?",
                        (amt_val, amt_val, acct),
                    )
                wal_after_image = self._get_double_entry_account(acct)
                batch_id = f"batch_{int(time.time()*1000)}_{blk['block_index']}"
                lsn = f"0/{int(time.time_ns()) & 0xFFFFFFFF:08X}"
                self.conn.execute(
                    "INSERT INTO wal_tuple_journal (tuple_id, batch_id, lsn, table_name, before_image_json, after_image_json, restored, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                    (
                        f"wal_{uuid.uuid4().hex[:12]}",
                        batch_id,
                        lsn,
                        (ast["target_tables"][0] if ast["target_tables"] else "ledger_accounts"),
                        json.dumps(wal_before_image),
                        json.dumps(wal_after_image),
                        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    ),
                )
                self.conn.execute(
                    "INSERT INTO rollback_batches (batch_id, account_id, amount, target_system, action, status, created_at) VALUES (?, ?, ?, ?, ?, 'STAGED', ?)",
                    (batch_id, acct, amt_val, target_sys_raw, ast["statement_type"], time.time()),
                )
                self.conn.commit()
            double_entry_acct = self._get_double_entry_account(acct) if verified else None

            total_ms = (time.perf_counter() - t0) * 1000.0
            return {
                "verdict": verdict,
                "verified": verified,
                "proof_id": proof_id,
                "proof_digest": digest,
                "unsat_core": core,
                "violation_reason": violation_reason,
                "counterfactual_patch": counterfactual_patch,
                "block_index": blk["block_index"],
                "block_hash": blk["block_hash"],
                "rfc6962_leaf_hash": blk.get("rfc6962_leaf_hash"),
                "rfc6962_tree_root": blk.get("rfc6962_tree_root"),
                "rollback_batch_id": batch_id,
                "escrow_status": escrow_status,
                "double_entry_account": double_entry_acct,
                "wal_before_image": wal_before_image,
                "dlp_checksums": dlp_checksums,
                "timings": {
                    "dlp_latency_ms": round(dlp_ms, 3),
                    "ast_latency_ms": round(ast_ms, 3),
                    "z3_solve_ms": round(z3_ms, 3),
                    "total_proxy_latency_ms": round(total_ms, 3),
                },
                "redactions": redactions,
                "sanitized_sql": sanitized_sql,
                "ast_analysis": ast,
            }

        if method == "rollback":
            t0 = time.perf_counter()
            batch_id = str(params.get("batchId", ""))
            if not batch_id:
                raise ValueError("batchId is required")
            row = self.conn.execute("SELECT * FROM rollback_batches WHERE batch_id = ?", (batch_id,)).fetchone()
            compensated = []
            escrow_res = "NOOP"
            restored_tuple: Optional[Dict[str, Any]] = None
            double_entry_acct: Optional[Dict[str, Any]] = None
            if row and row["status"] == "STAGED":
                ts_low = str(row["target_system"] or "").lower()
                is_esc = any(k in ts_low for k in ("stripe", "wire", "iso20022", "netsuite"))
                if is_esc:
                    self.conn.execute(
                        "UPDATE ledger_accounts SET balance = balance + ?, debits_pending = MAX(0.0, debits_pending - ?) WHERE account_id = ?",
                        (row["amount"], row["amount"], row["account_id"]),
                    )
                else:
                    self.conn.execute(
                        "UPDATE ledger_accounts SET balance = balance + ?, debits_posted = MAX(0.0, debits_posted - ?) WHERE account_id = ?",
                        (row["amount"], row["amount"], row["account_id"]),
                    )
                self.conn.execute(
                    "UPDATE rollback_batches SET status = 'ROLLED_BACK', rolled_back_at = ? WHERE batch_id = ?",
                    (time.time(), batch_id),
                )
                wal_row = self.conn.execute(
                    "SELECT before_image_json, lsn, table_name FROM wal_tuple_journal WHERE batch_id = ?",
                    (batch_id,),
                ).fetchone()
                if wal_row:
                    self.conn.execute("UPDATE wal_tuple_journal SET restored = 1 WHERE batch_id = ?", (batch_id,))
                    restored_tuple = {
                        "lsn": wal_row["lsn"],
                        "table_name": wal_row["table_name"],
                        "restored_before_image": json.loads(wal_row["before_image_json"]),
                    }
                self.conn.commit()
                double_entry_acct = self._get_double_entry_account(row["account_id"])
                escrow_res = "ESCROW_CANCELLED_PRE_DISPATCH" if is_esc else "SAVEPOINT_ROLLED_BACK"
                compensated.append({
                    "batch_id": batch_id,
                    "system": row["target_system"],
                    "amount_restored": row["amount"],
                    "status": "COMPENSATED",
                    "escrow_status": escrow_res,
                    "pgoutput_restored_tuple": restored_tuple,
                    "double_entry_account": double_entry_acct,
                })
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            ok = len(compensated) > 0
            valid, _, tip = self._verify_chain()
            blk = self._append_block(
                proof_id=f"rb_{batch_id}",
                action="ATOMIC_ROLLBACK",
                verdict="REVERTED" if ok else "NOOP",
                target_system="POSTGRESQL",
                zk_digest=tip,
                metadata={"batch_id": batch_id, "chain_valid": valid, "escrow_status": escrow_res},
            )
            return {
                "batch_id": batch_id,
                "success": ok,
                "actions_compensated": len(compensated),
                "escrow_status": escrow_res,
                "total_dispatch_ms": elapsed_ms,
                "sla_met": elapsed_ms < 38.0,
                "compensated_steps": compensated,
                "pgoutput_restored_tuple": restored_tuple,
                "double_entry_account": double_entry_acct,
                "audit_block_index": blk["block_index"],
                "audit_block_hash": blk["block_hash"],
                "rfc6962_leaf_hash": blk.get("rfc6962_leaf_hash"),
                "rfc6962_tree_root": blk.get("rfc6962_tree_root"),
            }

        if method == "verify_three_way_match":
            t0 = time.perf_counter()
            po = params["po"]
            receipts = params.get("receipts", [])
            invoices = params.get("invoices", [])
            tol = float(params.get("priceTolerancePct", 0.02))
            rec_qty = sum(float(r["receivedQty"]) for r in receipts if r["sku"] == po["sku"])
            bill_qty = sum(float(i["billedQty"]) for i in invoices if i["sku"] == po["sku"])
            avg_price = (
                sum(float(i["billedQty"]) * float(i["billedUnitPrice"]) for i in invoices if i["sku"] == po["sku"]) / bill_qty
                if bill_qty > 0
                else float(po["unitPrice"])
            )

            ctx = z3.Context()
            s = z3.Solver(ctx=ctx)
            z_po_q = z3.RealVal(str(float(po["orderedQty"])), ctx=ctx)
            z_rec_q = z3.RealVal(str(rec_qty), ctx=ctx)
            z_bill_q = z3.RealVal(str(bill_qty), ctx=ctx)
            z_po_p = z3.RealVal(str(float(po["unitPrice"])), ctx=ctx)
            z_bill_p = z3.RealVal(str(avg_price), ctx=ctx)

            s.assert_and_track(z_bill_q <= z_rec_q, "INV_BILLED_LE_RECEIVED")
            s.assert_and_track(z_bill_q <= z_po_q, "INV_BILLED_LE_ORDERED")
            s.assert_and_track(z_bill_p <= z_po_p * z3.RealVal(str(1.0 + tol), ctx=ctx), "INV_UNIT_PRICE_TOLERANCE")

            matched = s.check() == z3.sat
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            var_pct = round(((avg_price - float(po["unitPrice"])) / max(0.01, float(po["unitPrice"]))) * 100.0, 2)
            return {
                "matched": matched,
                "verdict": "SAT" if matched else "UNSAT",
                "sku": po["sku"],
                "po_qty": float(po["orderedQty"]),
                "received_qty": rec_qty,
                "billed_qty": bill_qty,
                "price_variance_pct": var_pct,
                "violated_rules": [] if matched else [str(c) for c in s.unsat_core()],
                "z3_solve_ms": elapsed_ms,
            }

        if method == "verify_tax_compliance":
            t0 = time.perf_counter()
            jur = str(params["jurisdiction"])
            lines = params.get("lines", [])
            has_stamp = bool(params.get("hasCryptographicStamp", True))
            tol = float(params.get("tolerance", 0.02))
            rate = {"EGYPT_ETA": 0.14, "KSA_ZATCA": 0.15, "EU_VAT_DE": 0.19, "EU_REVERSE_CHARGE": 0.0}.get(jur, 0.14)

            ctx = z3.Context()
            s = z3.Solver(ctx=ctx)
            exp_total = 0.0
            claimed_total = 0.0
            if jur == "KSA_ZATCA":
                s.assert_and_track(z3.BoolVal(has_stamp, ctx=ctx), "INV_ZATCA_CRYPTO_STAMP_REQUIRED")
            for idx, ln in enumerate(lines):
                net = float(ln["netAmount"])
                c_vat = float(ln["claimedVatAmount"])
                e_vat = 0.0 if ln.get("isExempt") else round(net * rate, 2)
                exp_total += e_vat
                claimed_total += c_vat
                diff = z3.RealVal(str(abs(c_vat - e_vat)), ctx=ctx)
                s.assert_and_track(diff <= z3.RealVal(str(tol), ctx=ctx), f"INV_TAX_LINE_{idx}_{jur}")

            ok = s.check() == z3.sat
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            core = [] if ok else [str(c) for c in s.unsat_core()]
            return {
                "jurisdiction": jur,
                "verdict": "SAT" if ok else "UNSAT",
                "verified": ok,
                "expected_total_vat": round(exp_total, 2),
                "claimed_total_vat": round(claimed_total, 2),
                "violated_tax_laws": core,
                "z3_solve_ms": elapsed_ms,
                "proof_hash": hashlib.sha256(f"{jur}:{exp_total}:{claimed_total}:{ok}".encode()).hexdigest(),
            }

        if method == "bitemporal_insert":
            eid = str(params["entityId"])
            vs = int(params["validStart"])
            ve = int(params.get("validEnd", 9999999999))
            if ve < 0:
                ve = 9999999999
            ss = int(params["systemTime"]) if params.get("systemTime") is not None else int(time.time())
            self.conn.execute(
                "INSERT INTO bitemporal_records (entity_id, data_json, valid_start, valid_end, system_start, system_end) VALUES (?, ?, ?, ?, ?, 9999999999)",
                (eid, json.dumps(params["data"]), vs, ve, ss),
            )
            self.conn.commit()
            return {"inserted": True, "entity_id": eid, "valid_start": vs, "system_start": ss}

        if method == "bitemporal_restate":
            eid = str(params["entityId"])
            vs = int(params["validStart"])
            ve = int(params.get("validEnd", 9999999999))
            if ve < 0:
                ve = 9999999999
            ss = int(params["systemTime"]) if params.get("systemTime") is not None else int(time.time())
            self.conn.execute(
                "UPDATE bitemporal_records SET system_end = ? WHERE entity_id = ? AND system_end = 9999999999",
                (ss, eid),
            )
            self.conn.execute(
                "INSERT INTO bitemporal_records (entity_id, data_json, valid_start, valid_end, system_start, system_end) VALUES (?, ?, ?, ?, ?, 9999999999)",
                (eid, json.dumps(params["data"]), vs, ve, ss),
            )
            self.conn.commit()
            return {"restated": True, "entity_id": eid, "valid_start": vs, "system_start": ss}

        if method == "bitemporal_as_of":
            eid = str(params["entityId"])
            vt = int(params["validTime"])
            st = int(params["systemTime"])
            row = self.conn.execute(
                """
                SELECT data_json FROM bitemporal_records
                WHERE entity_id = ?
                  AND valid_start <= ? AND ? < valid_end
                  AND system_start <= ? AND ? < system_end
                ORDER BY id DESC LIMIT 1
                """,
                (eid, vt, vt, st, st),
            ).fetchone()
            return {"found": row is not None, "data": json.loads(row["data_json"]) if row else None}

        if method == "verify_audit_chain":
            valid, cnt, tip = self._verify_chain()
            return {"valid": valid, "block_count": cnt, "tip_hash": tip}

        if method == "flush_escrow":
            t0 = time.perf_counter()
            cooling_sec = float(params.get("coolingWindowSec", 0.0))
            batch_id = str(params.get("batchId", "")).strip()
            cutoff = time.time() - max(0.0, cooling_sec)
            if batch_id:
                rows = self.conn.execute(
                    "SELECT * FROM rollback_batches WHERE batch_id = ? AND status = 'STAGED'",
                    (batch_id,),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM rollback_batches WHERE status = 'STAGED' AND created_at <= ? ORDER BY created_at ASC",
                    (cutoff,),
                ).fetchall()
            dispatched = []
            now = time.time()
            for row in rows:
                ts_low = str(row["target_system"] or "").lower()
                if not any(k in ts_low for k in ("stripe", "wire", "iso20022", "netsuite")) and not batch_id:
                    continue
                b_id = row["batch_id"]
                self.conn.execute(
                    "UPDATE ledger_accounts SET debits_pending = MAX(0.0, debits_pending - ?), debits_posted = debits_posted + ? WHERE account_id = ?",
                    (row["amount"], row["amount"], row["account_id"]),
                )
                self.conn.execute(
                    "UPDATE rollback_batches SET status = 'DISPATCHED_TO_RAIL', rolled_back_at = ? WHERE batch_id = ?",
                    (now, b_id),
                )
                rail_ref = f"iso20022_pain001_{b_id}" if ("wire" in ts_low or "iso20022" in ts_low) else f"po_stripe_{b_id}"
                dispatched.append({
                    "batch_id": b_id,
                    "account_id": row["account_id"],
                    "amount": row["amount"],
                    "target_system": row["target_system"],
                    "escrow_status": "DISPATCHED_TO_RAIL",
                    "settlement_reference": rail_ref,
                    "double_entry_account": self._get_double_entry_account(row["account_id"]),
                })
            self.conn.commit()
            valid, _, tip = self._verify_chain()
            blk = self._append_block(
                proof_id=f"escrow_flush_{int(now*1000)}",
                action="ESCROW_OUTBOX_SETTLEMENT_FLUSH",
                verdict="DISPATCHED" if dispatched else "NOOP",
                target_system="ESCROW_RAIL",
                zk_digest=tip,
                metadata={"flushed_count": len(dispatched), "chain_valid": valid},
            )
            return {
                "flushed_count": len(dispatched),
                "dispatched": dispatched,
                "escrow_status": "DISPATCHED_TO_RAIL" if dispatched else "NO_ELIGIBLE_ESCROW",
                "flush_latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                "audit_block_index": blk["block_index"],
                "audit_block_hash": blk["block_hash"],
                "rfc6962_leaf_hash": blk.get("rfc6962_leaf_hash"),
                "rfc6962_tree_root": blk.get("rfc6962_tree_root"),
            }

        if method == "merkle_inclusion_proof":
            block_idx_raw = params.get("blockIndex")
            block_idx = int(block_idx_raw) if block_idx_raw is not None else None
            return self.generate_rfc6962_inclusion_proof(block_idx)

        if method == "evaluate_policy":
            t0 = time.perf_counter()
            policy_text = str(params.get("policyText") or DEFAULT_ENTERPRISE_POLICY)
            action = str(params.get("action") or "UPDATE").upper()
            ctx_raw = params.get("context")
            ctx = dict(ctx_raw) if isinstance(ctx_raw, dict) else {}
            if "amount" in params and "amount" not in ctx:
                ctx["amount"] = params["amount"]
            if "currentBalance" in params and "current_balance" not in ctx:
                ctx["current_balance"] = params["currentBalance"]
            if "minReserve" in params and "min_reserve" not in ctx:
                ctx["min_reserve"] = params["minReserve"]
            if "spendingLimit" in params and "spending_limit" not in ctx:
                ctx["spending_limit"] = params["spendingLimit"]
            if "cfoSigned" in params and "cfo_signed" not in ctx:
                ctx["cfo_signed"] = params["cfoSigned"]
            if "reversalArmed" in params and "reversal_armed" not in ctx:
                ctx["reversal_armed"] = params["reversalArmed"]
            principal = params.get("principal") or ctx.get("principal")
            resource = params.get("resource") or ctx.get("resource")
            hierarchy = params.get("entityHierarchy") or params.get("entity_hierarchy") or ctx.get("entity_hierarchy")
            res = evaluate_policy_z3(
                policy_text=policy_text,
                action=action,
                context=ctx,
                principal=principal,
                resource=resource,
                entity_hierarchy=hierarchy,
            )
            digest = hashlib.sha256(
                json.dumps({"action": action, "principal": principal, "resource": resource, "verdict": res["verdict"]}, sort_keys=True).encode()
            ).hexdigest()
            blk = self._append_block(
                proof_id=f"pol_{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}",
                action="POLICY_EVAL",
                verdict=res["verdict"],
                target_system="POLICY_ENGINE",
                zk_digest=digest,
                metadata={
                    "principal": principal,
                    "resource": resource,
                    "unsat_core": res["unsat_core"],
                },
            )
            res["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
            res["block_index"] = blk["block_index"]
            res["block_hash"] = blk["block_hash"]
            res["rfc6962_leaf_hash"] = blk.get("rfc6962_leaf_hash")
            res["rfc6962_tree_root"] = blk.get("rfc6962_tree_root")
            return res

        raise ValueError(f"Unknown enclave method: {method}")


def main() -> None:
    session = StandaloneEnclaveSession()
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        req_id = None
        try:
            req = json.loads(line)
            req_id = req.get("id")
            result = session.handle(req.get("method", ""), req.get("params") or {})
            sys.stdout.write(json.dumps({"id": req_id, "result": result}) + "\n")
            sys.stdout.flush()
        except Exception as exc:
            sys.stdout.write(json.dumps({"id": req_id, "error": {"message": str(exc)}}) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
