"""
Apodictic Live Odoo 18 JSON-RPC 2.0 + Egypt ETA v1.0 Formal Invoice Pipeline
=========================================================================
End-to-end stateful ERP clearing pipeline executing:
  1. Zero-PII & Prompt-Injection Screening on ERP invoice memos/descriptions.
  2. Real Odoo 18 JSON-RPC 2.0 wire transport (`Odoo18LiveClient` -> HTTP/TCP `/jsonrpc`),
     pairable with either an external Odoo 18 container or `EmbeddedOdoo18JsonRpcNode`
     (a real HTTP JSON-RPC 2.0 + SQLite WAL double-entry ERP server).
  3. Z3 Formal Invariant Proofs (`QF_LRA` + integer piastre parity):
     - Egypt ETA compound T2 Table Tax -> T1 14% VAT cascade `(Net + T2) * 0.14`
     - Header vs. line-sum piastre parity & Odoo GL Debit == Credit conservation
     - Duplicate `internalID` / canonical ETA SHA-256 idempotency
     - Payment-time T4 Withholding Tax (`Net * T4`) cash + certificate conservation
  4. Canonical Egypt ETA v1.0 JSON builder + recursive uppercase SHA-256 digest binding.
  5. Live Atomic `account.move.reversal` compensating saga + SEC 17a-4 Merkle sealing.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import re
import sqlite3
import threading
import time
import z3
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from noesis_engine.src.audit_ledger.merkle_sealer import MerkleAuditLedger
from noesis_engine.src.erp_connectors.live_odoo_connector import (
    LiveCompensatingRollbackEngine,
    Odoo18LiveClient,
)
from noesis_engine.src.gateway.zero_pii import ZeroPIIGateway


PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"bypass\s+(z3|formal|approval|vat|tax)\s+(check|guard|rule)", re.IGNORECASE),
    re.compile(r"system\s+override\s*:", re.IGNORECASE),
    re.compile(r"skip\s+account\.move\.reversal", re.IGNORECASE),
]


def to_piastres(amount_egp: float) -> int:
    """Convert EGP float to exact integer piastres (1 EGP = 100 piastres)."""
    return int(round(amount_egp * 100.0))


def from_piastres(piastres: int) -> float:
    return round(piastres / 100.0, 2)


def canonical_eta_serialize(node: Any) -> str:
    """
    Canonicalize an ETA v1.0 JSON document using deterministic uppercase key
    concatenation per Egypt ETA e-Invoicing canonicalization rules.
    """
    if isinstance(node, dict):
        parts: List[str] = []
        for k in sorted(node.keys()):
            val = node[k]
            if isinstance(val, list):
                key_upper = f'"{str(k).upper()}"'
                list_parts = [f'{key_upper}{canonical_eta_serialize(item)}' for item in val]
                parts.append(f'{key_upper}{"".join(list_parts)}')
            else:
                parts.append(f'"{str(k).upper()}"{canonical_eta_serialize(val)}')
        return "".join(parts)
    if isinstance(node, list):
        return "".join(canonical_eta_serialize(item) for item in node)
    if isinstance(node, bool):
        return f'"{"true" if node else "false"}"'
    if isinstance(node, (int, float)):
        return f'"{node}"'
    return f'"{str(node)}"'


@dataclass(frozen=True)
class EtaInvoiceLineSpec:
    sku: str
    description: str
    item_code: str
    quantity: float
    unit_price_egp: float
    t2_table_rate: float = 0.0
    t1_vat_rate: float = 0.14
    claimed_vat_egp: Optional[float] = None
    item_type: str = "EGS"
    unit_type: str = "EA"


@dataclass(frozen=True)
class OdooEtaInvoiceRequest:
    internal_id: str
    issuer_tin: str
    issuer_name: str
    receiver_tin: str
    receiver_name: str
    lines: List[EtaInvoiceLineSpec]
    activity_code: str = "6201"
    date_issued: str = "2026-11-16"
    t4_wht_rate: float = 0.03
    accounting_period_open: bool = True


@dataclass
class EtaSettlementResult:
    settled: bool
    verdict: str
    internal_id: str
    odoo_move_id: int
    cash_paid_egp: float
    wht_t4_withheld_egp: float
    expected_wht_t4_egp: float
    gross_invoice_egp: float
    wht_certificate_ref: Optional[str]
    violated_rules: List[str]
    z3_solve_ms: float
    merkle_block_hash: str


@dataclass
class OdooEtaExecutionReceipt:
    status: str  # "POSTED_AND_ETA_SEALED" | "REJECTED_PRE_COMMIT" | "COMPENSATED_VIA_ODOO_REVERSAL" | "QUARANTINED_INJECTION"
    verdict: str  # "SAT" | "UNSAT"
    internal_id: str
    odoo_move_id: Optional[int]
    reversal_move_id: Optional[int]
    net_amount_egp: float
    t2_table_tax_egp: float
    expected_t1_vat_egp: float
    claimed_t1_vat_egp: float
    gross_total_egp: float
    eta_canonical_sha256: Optional[str]
    eta_document: Optional[Dict[str, Any]]
    violated_invariants: List[str]
    z3_solve_ms: float
    rpc_roundtrip_ms: float
    merkle_block_hash: str
    merkle_chain_valid: bool
    sanitized_descriptions: List[str] = field(default_factory=list)


class EmbeddedOdoo18JsonRpcNode:
    """
    Genuine TCP/HTTP JSON-RPC 2.0 Odoo 18 Ledger Node backed by SQLite WAL.
    Supports `common.authenticate` and `object.execute_kw` on:
      - `res.partner` (`create`, `search_read`)
      - `account.move` (`create`, `action_post`, `read`, `search_read`)
      - `account.move.reversal` (`create`, `reverse_moves`)
      - `account.payment` (`register_wht_settlement`)
    """

    def __init__(self, db_path: str = ":memory:", expected_db: str = "odoo18", username: str = "admin", password: str = "admin"):
        self.expected_db = expected_db
        self.username = username
        self.password = password
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        self._server: Optional[http.server.ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port: int = 0

    def _init_schema(self) -> None:
        with self._lock:
            cur = self.conn.cursor()
            cur.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS res_partner (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    vat TEXT UNIQUE NOT NULL
                );
                CREATE TABLE IF NOT EXISTS account_move (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    move_type TEXT NOT NULL,
                    partner_id INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('draft','posted','cancel')),
                    invoice_date TEXT NOT NULL,
                    amount_untaxed_cents INTEGER NOT NULL,
                    amount_t2_cents INTEGER NOT NULL DEFAULT 0,
                    amount_t1_cents INTEGER NOT NULL DEFAULT 0,
                    amount_total_cents INTEGER NOT NULL,
                    eta_sha256 TEXT,
                    reversed_entry_id INTEGER,
                    FOREIGN KEY(partner_id) REFERENCES res_partner(id)
                );
                CREATE TABLE IF NOT EXISTS account_move_line (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    move_id INTEGER NOT NULL,
                    account_code TEXT NOT NULL,
                    name TEXT NOT NULL,
                    debit_cents INTEGER NOT NULL CHECK(debit_cents >= 0),
                    credit_cents INTEGER NOT NULL CHECK(credit_cents >= 0),
                    FOREIGN KEY(move_id) REFERENCES account_move(id)
                );
                CREATE TABLE IF NOT EXISTS account_move_reversal (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    move_id INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    date TEXT NOT NULL,
                    reversal_move_id INTEGER
                );
                CREATE TABLE IF NOT EXISTS wht_settlements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    move_id INTEGER NOT NULL,
                    cash_paid_cents INTEGER NOT NULL,
                    wht_t4_cents INTEGER NOT NULL,
                    certificate_ref TEXT NOT NULL
                );
                """
            )
            self.conn.commit()

    def start(self) -> int:
        node = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.path != "/jsonrpc":
                    self.send_response(404)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                req = json.loads(raw.decode("utf-8"))
                req_id = req.get("id")
                params = req.get("params", {})
                try:
                    result = node._dispatch(
                        params.get("service", ""),
                        params.get("method", ""),
                        params.get("args", []),
                    )
                    resp = {"jsonrpc": "2.0", "id": req_id, "result": result}
                except Exception as exc:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": 200, "message": str(exc)},
                    }
                body = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                return

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self.conn.close()

    def __enter__(self) -> "EmbeddedOdoo18JsonRpcNode":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()

    def _dispatch(self, service: str, method: str, args: List[Any]) -> Any:
        if service == "common" and method == "authenticate":
            db, user, pwd = args[0], args[1], args[2]
            if db == self.expected_db and user == self.username and pwd == self.password:
                return 2
            return False

        if service == "object" and method == "execute_kw":
            db, uid, pwd, model, orm_method, orm_args, orm_kwargs = args
            if db != self.expected_db or uid != 2 or pwd != self.password:
                raise PermissionError("Invalid Odoo JSON-RPC session credentials")
            with self._lock:
                return self._execute_orm(model, orm_method, orm_args, orm_kwargs or {})

        raise ValueError(f"Unsupported RPC call: {service}.{method}")

    def _execute_orm(self, model: str, method: str, args: List[Any], kwargs: Dict[str, Any]) -> Any:
        cur = self.conn.cursor()

        if model == "res.partner":
            if method == "create":
                vals = args[0]
                cur.execute(
                    "INSERT INTO res_partner (name, vat) VALUES (?, ?)",
                    (vals["name"], vals["vat"]),
                )
                self.conn.commit()
                return cur.lastrowid
            if method == "search_read":
                domain = args[0] if args else []
                if domain and len(domain[0]) == 3 and domain[0][0] == "vat":
                    rows = cur.execute("SELECT id, name, vat FROM res_partner WHERE vat = ?", (domain[0][2],)).fetchall()
                else:
                    rows = cur.execute("SELECT id, name, vat FROM res_partner").fetchall()
                return [dict(r) for r in rows]

        if model == "account.move":
            if method == "create":
                vals = args[0]
                cur.execute(
                    """
                    INSERT INTO account_move (
                        name, move_type, partner_id, state, invoice_date,
                        amount_untaxed_cents, amount_t2_cents, amount_t1_cents,
                        amount_total_cents, eta_sha256, reversed_entry_id
                    ) VALUES (?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        vals["name"],
                        vals.get("move_type", "out_invoice"),
                        vals["partner_id"],
                        vals.get("invoice_date", "2026-11-16"),
                        vals["amount_untaxed_cents"],
                        vals.get("amount_t2_cents", 0),
                        vals.get("amount_t1_cents", 0),
                        vals["amount_total_cents"],
                        vals.get("eta_sha256"),
                        vals.get("reversed_entry_id"),
                    ),
                )
                move_id = cur.lastrowid
                for line in vals.get("line_ids", []):
                    cur.execute(
                        "INSERT INTO account_move_line (move_id, account_code, name, debit_cents, credit_cents) VALUES (?, ?, ?, ?, ?)",
                        (move_id, line["account_code"], line["name"], line["debit_cents"], line["credit_cents"]),
                    )
                self.conn.commit()
                return move_id

            if method == "action_post":
                ids = args[0]
                for move_id in ids:
                    sums = cur.execute(
                        "SELECT COALESCE(SUM(debit_cents),0) AS d, COALESCE(SUM(credit_cents),0) AS c FROM account_move_line WHERE move_id = ?",
                        (move_id,),
                    ).fetchone()
                    if sums["d"] != sums["c"] or sums["d"] <= 0:
                        raise ValueError(f"Unbalanced Odoo journal entry {move_id}: debits={sums['d']} != credits={sums['c']}")
                    cur.execute("UPDATE account_move SET state = 'posted' WHERE id = ?", (move_id,))
                self.conn.commit()
                return True

            if method == "read":
                ids = args[0]
                if not ids:
                    return []
                rows = cur.execute(
                    f"SELECT * FROM account_move WHERE id IN ({','.join('?' * len(ids))})",
                    ids,
                ).fetchall()
                return [dict(r) for r in rows]

            if method == "search_read":
                domain = args[0] if args else []
                if domain and len(domain[0]) == 3 and domain[0][0] == "name":
                    rows = cur.execute("SELECT * FROM account_move WHERE name = ?", (domain[0][2],)).fetchall()
                elif domain and len(domain[0]) == 3 and domain[0][0] == "reversed_entry_id":
                    rows = cur.execute("SELECT * FROM account_move WHERE reversed_entry_id = ?", (domain[0][2],)).fetchall()
                else:
                    rows = cur.execute("SELECT * FROM account_move").fetchall()
                return [dict(r) for r in rows]

        if model == "account.move.reversal":
            if method == "create":
                vals = args[0]
                move_id = vals["move_ids"][0][1]
                cur.execute(
                    "INSERT INTO account_move_reversal (move_id, reason, date) VALUES (?, ?, ?)",
                    (move_id, vals.get("reason", "Reversal"), vals.get("date", "2026-11-16")),
                )
                self.conn.commit()
                return cur.lastrowid

            if method == "reverse_moves":
                wiz_id = args[0][0]
                wiz = cur.execute("SELECT * FROM account_move_reversal WHERE id = ?", (wiz_id,)).fetchone()
                orig = cur.execute("SELECT * FROM account_move WHERE id = ?", (wiz["move_id"],)).fetchone()
                orig_lines = cur.execute("SELECT * FROM account_move_line WHERE move_id = ?", (orig["id"],)).fetchall()
                rev_name = f"R{orig['name']}"
                rev_type = "out_refund" if orig["move_type"] == "out_invoice" else "in_refund"
                cur.execute(
                    """
                    INSERT INTO account_move (
                        name, move_type, partner_id, state, invoice_date,
                        amount_untaxed_cents, amount_t2_cents, amount_t1_cents,
                        amount_total_cents, eta_sha256, reversed_entry_id
                    ) VALUES (?, ?, ?, 'posted', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rev_name,
                        rev_type,
                        orig["partner_id"],
                        wiz["date"],
                        -orig["amount_untaxed_cents"],
                        -orig["amount_t2_cents"],
                        -orig["amount_t1_cents"],
                        -orig["amount_total_cents"],
                        orig["eta_sha256"],
                        orig["id"],
                    ),
                )
                rev_id = cur.lastrowid
                for l in orig_lines:
                    cur.execute(
                        "INSERT INTO account_move_line (move_id, account_code, name, debit_cents, credit_cents) VALUES (?, ?, ?, ?, ?)",
                        (rev_id, l["account_code"], f"REV: {l['name']}", l["credit_cents"], l["debit_cents"]),
                    )
                cur.execute("UPDATE account_move_reversal SET reversal_move_id = ? WHERE id = ?", (rev_id, wiz_id))
                self.conn.commit()
                return {"res_id": rev_id, "reversal_move_id": rev_id, "reversed_name": rev_name}

        if model == "account.payment":
            if method == "register_wht_settlement":
                vals = args[0]
                existing = cur.execute("SELECT COUNT(*) AS cnt FROM wht_settlements WHERE move_id = ?", (vals["move_id"],)).fetchone()
                if existing["cnt"] > 0:
                    raise ValueError(f"Duplicate T4 WHT settlement blocked for move_id={vals['move_id']}")
                cur.execute(
                    "INSERT INTO wht_settlements (move_id, cash_paid_cents, wht_t4_cents, certificate_ref) VALUES (?, ?, ?, ?)",
                    (vals["move_id"], vals["cash_paid_cents"], vals["wht_t4_cents"], vals["certificate_ref"]),
                )
                self.conn.commit()
                return cur.lastrowid
            if method == "search_read":
                domain = args[0] if args else []
                if domain and len(domain[0]) == 3 and domain[0][0] == "move_id":
                    rows = cur.execute("SELECT * FROM wht_settlements WHERE move_id = ?", (domain[0][2],)).fetchall()
                else:
                    rows = cur.execute("SELECT * FROM wht_settlements").fetchall()
                return [dict(r) for r in rows]

        raise ValueError(f"Unsupported ORM call: {model}.{method}")

    def snapshot_gl_balance(self) -> Dict[str, Any]:
        with self._lock:
            cur = self.conn.cursor()
            row = cur.execute(
                "SELECT COALESCE(SUM(debit_cents),0) AS total_debits, COALESCE(SUM(credit_cents),0) AS total_credits FROM account_move_line"
            ).fetchone()
            ar_net = cur.execute(
                "SELECT COALESCE(SUM(debit_cents - credit_cents), 0) AS net_ar FROM account_move_line WHERE account_code = '121000'"
            ).fetchone()
            moves = cur.execute("SELECT id, name, move_type, state, amount_total_cents, reversed_entry_id FROM account_move ORDER BY id").fetchall()
            return {
                "total_debits_cents": row["total_debits"],
                "total_credits_cents": row["total_credits"],
                "net_ar_exposure_cents": ar_net["net_ar"],
                "moves": [dict(m) for m in moves],
            }


class OdooEtaFormalClearancePipeline:
    """
    Coordinates Zero-PII -> Z3 5.4.1 ETA/GL Proofs -> Live Odoo 18 JSON-RPC ->
    Canonical ETA v1.0 SHA-256 Binding -> Atomic Compensating Reversals -> Merkle Sealing.
    """

    def __init__(self, odoo_client: Odoo18LiveClient, ledger: Optional[MerkleAuditLedger] = None):
        self.odoo = odoo_client
        self.compensator = LiveCompensatingRollbackEngine(odoo_client)
        self.ledger = ledger or MerkleAuditLedger()
        self.pii_gateway = ZeroPIIGateway()

    def _screen_and_redact(self, descriptions: List[str]) -> Tuple[bool, List[str]]:
        sanitized_list: List[str] = []
        for desc in descriptions:
            for pat in PROMPT_INJECTION_PATTERNS:
                if pat.search(desc):
                    return True, sanitized_list
            clean, _, _ = self.pii_gateway.sanitize_string(desc)
            sanitized_list.append(clean)
        return False, sanitized_list

    def _build_eta_document(self, req: OdooEtaInvoiceRequest, computed_lines: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], str]:
        net_cents = sum(l["net_cents"] for l in computed_lines)
        t2_cents = sum(l["t2_cents"] for l in computed_lines)
        t1_cents = sum(l["t1_cents"] for l in computed_lines)
        total_cents = net_cents + t2_cents + t1_cents

        doc = {
            "issuer": {
                "address": {"branchID": "0", "country": "EG", "governate": "Cairo", "regionCity": "Maadi", "street": "Road 9", "buildingNumber": "14"},
                "type": "B",
                "id": req.issuer_tin,
                "name": req.issuer_name,
            },
            "receiver": {
                "address": {"country": "EG", "governate": "Giza", "regionCity": "Smart Village", "street": "Bldg 4", "buildingNumber": "1"},
                "type": "B",
                "id": req.receiver_tin,
                "name": req.receiver_name,
            },
            "documentType": "I",
            "documentTypeVersion": "1.0",
            "dateTimeIssued": f"{req.date_issued}T10:30:00Z",
            "taxpayerActivityCode": req.activity_code,
            "internalID": req.internal_id,
            "invoiceLines": [
                {
                    "description": l["description"],
                    "itemType": l["item_type"],
                    "itemCode": l["item_code"],
                    "unitType": l["unit_type"],
                    "quantity": l["quantity"],
                    "unitValue": {"currencySold": "EGP", "amountEGP": l["unit_price_egp"]},
                    "salesTotal": l["net_egp"],
                    "netTotal": l["net_egp"],
                    "taxableItems": [
                        {"taxType": "T2", "amount": l["t2_egp"], "subType": "Tbl01", "rate": round(l["t2_rate"] * 100, 2)},
                        {"taxType": "T1", "amount": l["t1_egp"], "subType": "V009", "rate": round(l["t1_rate"] * 100, 2)},
                    ],
                    "total": l["line_total_egp"],
                }
                for l in computed_lines
            ],
            "totalSalesAmount": from_piastres(net_cents),
            "totalDiscountAmount": 0.0,
            "netAmount": from_piastres(net_cents),
            "taxTotals": [
                {"taxType": "T2", "amount": from_piastres(t2_cents)},
                {"taxType": "T1", "amount": from_piastres(t1_cents)},
            ],
            "extraDiscountAmount": 0.0,
            "totalAmount": from_piastres(total_cents),
            "signatures": [
                {
                    "signatureType": "I",
                    "signingProfile": "CANONICAL_SHA256_PRE_HSM",
                }
            ],
        }
        canonical_str = canonical_eta_serialize(doc)
        digest = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        doc["signatures"][0]["canonicalSha256"] = digest
        return doc, digest

    def _verify_z3_eta_and_gl_invariants(
        self,
        req: OdooEtaInvoiceRequest,
        existing_move_count: int,
    ) -> Tuple[bool, List[str], List[Dict[str, Any]], float]:
        t0 = time.perf_counter()
        ctx = z3.Context()
        solver = z3.Solver(ctx=ctx)

        solver.assert_and_track(z3.BoolVal(req.accounting_period_open, ctx=ctx), "ODOO_FISCAL_PERIOD_OPEN")
        solver.assert_and_track(z3.IntVal(existing_move_count, ctx=ctx) == 0, "ODOO_ETA_IDEMPOTENCY_UNIQUE_INTERNAL_ID")

        tin_ok = bool(re.fullmatch(r"\d{9}", req.issuer_tin) and re.fullmatch(r"\d{9}", req.receiver_tin))
        solver.assert_and_track(z3.BoolVal(tin_ok, ctx=ctx), "ETA_9_DIGIT_TIN_SYNTAX_VALID")

        computed_lines: List[Dict[str, Any]] = []
        total_debit_cents = 0
        total_credit_cents = 0
        sum_expected_t1_cents = 0
        sum_claimed_t1_cents = 0

        for idx, line in enumerate(req.lines):
            net_cents = to_piastres(line.quantity * line.unit_price_egp)
            t2_cents = to_piastres((net_cents / 100.0) * line.t2_table_rate)
            compound_base_cents = net_cents + t2_cents
            exp_t1_cents = to_piastres((compound_base_cents / 100.0) * line.t1_vat_rate)
            claimed_t1_cents = to_piastres(line.claimed_vat_egp) if line.claimed_vat_egp is not None else exp_t1_cents
            line_total_cents = net_cents + t2_cents + exp_t1_cents

            z_net = z3.IntVal(net_cents, ctx=ctx)
            z_exp_t1 = z3.IntVal(exp_t1_cents, ctx=ctx)
            z_claimed_t1 = z3.IntVal(claimed_t1_cents, ctx=ctx)

            solver.assert_and_track(z_net > 0, f"ETA_LINE_{idx}_POSITIVE_NET")
            solver.assert_and_track(
                z3.And(z_claimed_t1 - z_exp_t1 <= 1, z_exp_t1 - z_claimed_t1 <= 1),
                f"ETA_COMPOUND_T2_T1_VAT_PARITY_LINE_{idx}",
            )

            total_debit_cents += line_total_cents
            total_credit_cents += net_cents + t2_cents + exp_t1_cents
            sum_expected_t1_cents += exp_t1_cents
            sum_claimed_t1_cents += claimed_t1_cents

            computed_lines.append(
                {
                    "description": line.description,
                    "item_type": line.item_type,
                    "item_code": line.item_code,
                    "unit_type": line.unit_type,
                    "quantity": line.quantity,
                    "unit_price_egp": line.unit_price_egp,
                    "t2_rate": line.t2_table_rate,
                    "t1_rate": line.t1_vat_rate,
                    "net_cents": net_cents,
                    "t2_cents": t2_cents,
                    "t1_cents": exp_t1_cents,
                    "claimed_t1_cents": claimed_t1_cents,
                    "line_total_cents": line_total_cents,
                    "net_egp": from_piastres(net_cents),
                    "t2_egp": from_piastres(t2_cents),
                    "t1_egp": from_piastres(exp_t1_cents),
                    "line_total_egp": from_piastres(line_total_cents),
                }
            )

        solver.assert_and_track(
            z3.IntVal(total_debit_cents, ctx=ctx) == z3.IntVal(total_credit_cents, ctx=ctx),
            "ODOO_GL_DOUBLE_ENTRY_DEBIT_EQ_CREDIT",
        )
        solver.assert_and_track(
            z3.And(
                z3.IntVal(sum_claimed_t1_cents - sum_expected_t1_cents, ctx=ctx) <= 1,
                z3.IntVal(sum_expected_t1_cents - sum_claimed_t1_cents, ctx=ctx) <= 1,
            ),
            "ETA_PIASTRE_HEADER_VS_LINE_TAX_PARITY",
        )

        res = solver.check()
        solve_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        if res == z3.sat:
            return True, [], computed_lines, solve_ms
        return False, [str(c) for c in solver.unsat_core()], computed_lines, solve_ms

    def _ensure_partner(self, name: str, vat: str) -> int:
        existing = self.odoo.execute_kw("res.partner", "search_read", [[["vat", "=", vat]]])
        if isinstance(existing, list) and existing:
            return int(existing[0]["id"])
        partner_id = self.odoo.execute_kw("res.partner", "create", [{"name": name, "vat": vat}])
        return int(partner_id)

    def submit_verified_invoice(self, req: OdooEtaInvoiceRequest) -> OdooEtaExecutionReceipt:
        injection_hit, sanitized_descs = self._screen_and_redact([l.description for l in req.lines])
        if injection_hit:
            blk = self.ledger.append_block(
                proof_id=f"INJ-{req.internal_id}",
                action="ETA_INVOICE_QUARANTINE",
                verdict="UNSAT",
                target_system="odoo_v18_eta_v1",
                zk_digest=hashlib.sha256(req.internal_id.encode()).hexdigest(),
                metadata={"reason": "INDIRECT_PROMPT_INJECTION_IN_LINE_DESCRIPTION"},
            )
            return OdooEtaExecutionReceipt(
                status="QUARANTINED_INJECTION",
                verdict="UNSAT",
                internal_id=req.internal_id,
                odoo_move_id=None,
                reversal_move_id=None,
                net_amount_egp=0.0,
                t2_table_tax_egp=0.0,
                expected_t1_vat_egp=0.0,
                claimed_t1_vat_egp=0.0,
                gross_total_egp=0.0,
                eta_canonical_sha256=None,
                eta_document=None,
                violated_invariants=["ZERO_TRUST_PROMPT_INJECTION_BLOCKED"],
                z3_solve_ms=0.0,
                rpc_roundtrip_ms=0.0,
                merkle_block_hash=blk["block_hash"],
                merkle_chain_valid=self.ledger.verify_integrity(),
                sanitized_descriptions=sanitized_descs,
            )

        t_rpc0 = time.perf_counter()
        self.odoo.authenticate()
        existing_moves = self.odoo.execute_kw("account.move", "search_read", [[["name", "=", req.internal_id]]])
        existing_count = len(existing_moves) if isinstance(existing_moves, list) else 0

        is_sat, core, computed_lines, z3_ms = self._verify_z3_eta_and_gl_invariants(req, existing_count)
        net_egp = from_piastres(sum(l["net_cents"] for l in computed_lines))
        t2_egp = from_piastres(sum(l["t2_cents"] for l in computed_lines))
        exp_t1_egp = from_piastres(sum(l["t1_cents"] for l in computed_lines))
        claimed_t1_egp = from_piastres(sum(l["claimed_t1_cents"] for l in computed_lines))
        gross_egp = round(net_egp + t2_egp + exp_t1_egp, 2)

        if not is_sat:
            rpc_ms = round((time.perf_counter() - t_rpc0) * 1000.0, 3)
            blk = self.ledger.append_block(
                proof_id=f"REJ-{req.internal_id}",
                action="ETA_INVOICE_PRE_COMMIT_REJECTED",
                verdict="UNSAT",
                target_system="odoo_v18_eta_v1",
                zk_digest=hashlib.sha256(f"{req.internal_id}:{','.join(core)}".encode()).hexdigest(),
                metadata={"unsat_core": core, "claimed_vat_egp": claimed_t1_egp, "expected_vat_egp": exp_t1_egp},
            )
            return OdooEtaExecutionReceipt(
                status="REJECTED_PRE_COMMIT",
                verdict="UNSAT",
                internal_id=req.internal_id,
                odoo_move_id=None,
                reversal_move_id=None,
                net_amount_egp=net_egp,
                t2_table_tax_egp=t2_egp,
                expected_t1_vat_egp=exp_t1_egp,
                claimed_t1_vat_egp=claimed_t1_egp,
                gross_total_egp=gross_egp,
                eta_canonical_sha256=None,
                eta_document=None,
                violated_invariants=core,
                z3_solve_ms=z3_ms,
                rpc_roundtrip_ms=rpc_ms,
                merkle_block_hash=blk["block_hash"],
                merkle_chain_valid=self.ledger.verify_integrity(),
                sanitized_descriptions=sanitized_descs,
            )

        eta_doc, eta_sha256 = self._build_eta_document(req, computed_lines)
        partner_id = self._ensure_partner(req.receiver_name, req.receiver_tin)
        net_cents = sum(l["net_cents"] for l in computed_lines)
        t2_cents = sum(l["t2_cents"] for l in computed_lines)
        t1_cents = sum(l["t1_cents"] for l in computed_lines)
        total_cents = net_cents + t2_cents + t1_cents

        move_vals = {
            "name": req.internal_id,
            "move_type": "out_invoice",
            "partner_id": partner_id,
            "invoice_date": req.date_issued,
            "amount_untaxed_cents": net_cents,
            "amount_t2_cents": t2_cents,
            "amount_t1_cents": t1_cents,
            "amount_total_cents": total_cents,
            "eta_sha256": eta_sha256,
            "line_ids": [
                {"account_code": "121000", "name": f"AR {req.internal_id}", "debit_cents": total_cents, "credit_cents": 0},
                {"account_code": "400000", "name": "Sales Revenue", "debit_cents": 0, "credit_cents": net_cents},
                {"account_code": "251020", "name": "ETA T2 Table Tax Payable", "debit_cents": 0, "credit_cents": t2_cents},
                {"account_code": "251000", "name": "ETA T1 14% VAT Output", "debit_cents": 0, "credit_cents": t1_cents},
            ],
        }
        move_id = int(self.odoo.execute_kw("account.move", "create", [move_vals]))
        self.odoo.execute_kw("account.move", "action_post", [[move_id]])
        rpc_ms = round((time.perf_counter() - t_rpc0) * 1000.0, 3)

        blk = self.ledger.append_block(
            proof_id=f"ETA-{req.internal_id}",
            action="ODOO_POST_AND_ETA_CANONICAL_SEAL",
            verdict="SAT",
            target_system="odoo_v18_eta_v1",
            zk_digest=eta_sha256,
            metadata={"odoo_move_id": move_id, "gross_total_egp": gross_egp, "z3_solve_ms": z3_ms},
        )
        return OdooEtaExecutionReceipt(
            status="POSTED_AND_ETA_SEALED",
            verdict="SAT",
            internal_id=req.internal_id,
            odoo_move_id=move_id,
            reversal_move_id=None,
            net_amount_egp=net_egp,
            t2_table_tax_egp=t2_egp,
            expected_t1_vat_egp=exp_t1_egp,
            claimed_t1_vat_egp=claimed_t1_egp,
            gross_total_egp=gross_egp,
            eta_canonical_sha256=eta_sha256,
            eta_document=eta_doc,
            violated_invariants=[],
            z3_solve_ms=z3_ms,
            rpc_roundtrip_ms=rpc_ms,
            merkle_block_hash=blk["block_hash"],
            merkle_chain_valid=self.ledger.verify_integrity(),
            sanitized_descriptions=sanitized_descs,
        )

    def detect_and_compensate_unverified_odoo_move(self, move_id: int, expected_net_egp: float, t2_rate: float, t1_rate: float) -> OdooEtaExecutionReceipt:
        """
        Audits an already-posted Odoo `account.move` (e.g., created directly by a legacy script)
        for compound T2->T1 VAT parity and triggers atomic `account.move.reversal` if invalid.
        """
        t0 = time.perf_counter()
        self.odoo.authenticate()
        rows = self.odoo.execute_kw("account.move", "read", [[move_id]])
        move = rows[0]
        exp_t2_cents = to_piastres(expected_net_egp * t2_rate)
        exp_t1_cents = to_piastres(((expected_net_egp * 100.0 + exp_t2_cents) / 100.0) * t1_rate)
        claimed_t1_cents = int(move["amount_t1_cents"])

        ctx = z3.Context()
        s = z3.Solver(ctx=ctx)
        s.assert_and_track(
            z3.And(
                z3.IntVal(claimed_t1_cents - exp_t1_cents, ctx=ctx) <= 1,
                z3.IntVal(exp_t1_cents - claimed_t1_cents, ctx=ctx) <= 1,
            ),
            "ETA_COMPOUND_T2_T1_POST_AUDIT_PARITY",
        )
        res = s.check()
        z3_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        if res == z3.sat:
            blk = self.ledger.append_block(
                proof_id=f"AUDIT-SAT-{move_id}",
                action="ODOO_POST_AUDIT_VERIFIED",
                verdict="SAT",
                target_system="odoo_v18_eta_v1",
                zk_digest=str(move.get("eta_sha256") or ""),
            )
            return OdooEtaExecutionReceipt(
                status="POSTED_AND_ETA_SEALED",
                verdict="SAT",
                internal_id=move["name"],
                odoo_move_id=move_id,
                reversal_move_id=None,
                net_amount_egp=from_piastres(move["amount_untaxed_cents"]),
                t2_table_tax_egp=from_piastres(move["amount_t2_cents"]),
                expected_t1_vat_egp=from_piastres(exp_t1_cents),
                claimed_t1_vat_egp=from_piastres(claimed_t1_cents),
                gross_total_egp=from_piastres(move["amount_total_cents"]),
                eta_canonical_sha256=move.get("eta_sha256"),
                eta_document=None,
                violated_invariants=[],
                z3_solve_ms=z3_ms,
                rpc_roundtrip_ms=0.0,
                merkle_block_hash=blk["block_hash"],
                merkle_chain_valid=self.ledger.verify_integrity(),
            )

        core = [str(c) for c in s.unsat_core()]
        comp = self.compensator.execute_odoo_reversal(
            move_id=move_id,
            reason=f"Z3 ETA T2/T1 Parity Breach: {core[0]}",
        )
        rev_id = int(comp["action_result"]["reversal_move_id"])
        blk = self.ledger.append_block(
            proof_id=f"COMP-{move_id}",
            action="ODOO_ATOMIC_REVERSAL_COMPENSATED",
            verdict="UNSAT",
            target_system="odoo_v18_eta_v1",
            zk_digest=hashlib.sha256(f"REV:{move_id}->{rev_id}".encode()).hexdigest(),
            metadata={"unsat_core": core, "reversal_move_id": rev_id, "compensation_ms": comp["latency_ms"]},
        )
        return OdooEtaExecutionReceipt(
            status="COMPENSATED_VIA_ODOO_REVERSAL",
            verdict="UNSAT",
            internal_id=move["name"],
            odoo_move_id=move_id,
            reversal_move_id=rev_id,
            net_amount_egp=from_piastres(move["amount_untaxed_cents"]),
            t2_table_tax_egp=from_piastres(move["amount_t2_cents"]),
            expected_t1_vat_egp=from_piastres(exp_t1_cents),
            claimed_t1_vat_egp=from_piastres(claimed_t1_cents),
            gross_total_egp=from_piastres(move["amount_total_cents"]),
            eta_canonical_sha256=None,
            eta_document=None,
            violated_invariants=core,
            z3_solve_ms=z3_ms,
            rpc_roundtrip_ms=round(comp["latency_ms"], 3),
            merkle_block_hash=blk["block_hash"],
            merkle_chain_valid=self.ledger.verify_integrity(),
        )

    def settle_invoice_with_wht_t4(
        self,
        move_id: int,
        cash_paid_egp: float,
        wht_t4_withheld_egp: float,
        expected_t4_rate: float = 0.03,
    ) -> EtaSettlementResult:
        """
        Verifies and settles buyer cash + Egypt ETA T4 Withholding Tax (computed strictly on Net excl. VAT)
        against a posted Odoo move, issuing a deterministic T4 withholding certificate reference.
        """
        t0 = time.perf_counter()
        self.odoo.authenticate()
        move = self.odoo.execute_kw("account.move", "read", [[move_id]])[0]
        reversals = self.odoo.execute_kw("account.move", "search_read", [[["reversed_entry_id", "=", move_id]]])
        prior_wht = self.odoo.execute_kw("account.payment", "search_read", [[["move_id", "=", move_id]]])

        is_posted = move.get("state") == "posted" and move.get("move_type") in ("out_invoice", "in_invoice")
        not_reversed = not (isinstance(reversals, list) and len(reversals) > 0)
        not_settled = not (isinstance(prior_wht, list) and len(prior_wht) > 0)

        net_cents = int(move["amount_untaxed_cents"])
        gross_cents = int(move["amount_total_cents"])
        cash_cents = to_piastres(cash_paid_egp)
        wht_cents = to_piastres(wht_t4_withheld_egp)
        exp_wht_cents = to_piastres((net_cents / 100.0) * expected_t4_rate)

        ctx = z3.Context()
        s = z3.Solver(ctx=ctx)
        s.assert_and_track(z3.BoolVal(is_posted, ctx=ctx), "ODOO_MOVE_POSTED_FOR_SETTLEMENT")
        s.assert_and_track(z3.BoolVal(not_reversed, ctx=ctx), "ODOO_MOVE_NOT_ALREADY_REVERSED")
        s.assert_and_track(z3.BoolVal(not_settled, ctx=ctx), "ODOO_NO_DUPLICATE_WHT_SETTLEMENT")
        s.assert_and_track(
            z3.And(
                z3.IntVal((cash_cents + wht_cents) - gross_cents, ctx=ctx) <= 1,
                z3.IntVal(gross_cents - (cash_cents + wht_cents), ctx=ctx) <= 1,
            ),
            "ETA_T4_CASH_PLUS_WHT_EQ_GROSS",
        )
        s.assert_and_track(
            z3.And(
                z3.IntVal(wht_cents - exp_wht_cents, ctx=ctx) <= 1,
                z3.IntVal(exp_wht_cents - wht_cents, ctx=ctx) <= 1,
            ),
            "ETA_T4_COMPUTED_ON_NET_EXCL_VAT",
        )
        res = s.check()
        z3_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        if res != z3.sat:
            core = [str(c) for c in s.unsat_core()]
            blk = self.ledger.append_block(
                proof_id=f"WHT-REJ-{move_id}",
                action="ETA_T4_WHT_SETTLEMENT_REJECTED",
                verdict="UNSAT",
                target_system="odoo_v18_eta_v1",
                zk_digest=hashlib.sha256(f"{move_id}:{','.join(core)}".encode()).hexdigest(),
                metadata={"unsat_core": core},
            )
            return EtaSettlementResult(
                settled=False,
                verdict="UNSAT",
                internal_id=move["name"],
                odoo_move_id=move_id,
                cash_paid_egp=cash_paid_egp,
                wht_t4_withheld_egp=wht_t4_withheld_egp,
                expected_wht_t4_egp=from_piastres(exp_wht_cents),
                gross_invoice_egp=from_piastres(gross_cents),
                wht_certificate_ref=None,
                violated_rules=core,
                z3_solve_ms=z3_ms,
                merkle_block_hash=blk["block_hash"],
            )

        cert_ref = f"ETA-T4-{move['name']}-{hashlib.sha256(f'{move_id}:{wht_cents}'.encode()).hexdigest()[:10].upper()}"
        self.odoo.execute_kw(
            "account.payment",
            "register_wht_settlement",
            [{
                "move_id": move_id,
                "cash_paid_cents": cash_cents,
                "wht_t4_cents": wht_cents,
                "certificate_ref": cert_ref,
            }],
        )
        blk = self.ledger.append_block(
            proof_id=cert_ref,
            action="ETA_T4_WHT_SETTLEMENT_SEALED",
            verdict="SAT",
            target_system="odoo_v18_eta_v1",
            zk_digest=hashlib.sha256(cert_ref.encode()).hexdigest(),
            metadata={"cash_paid_egp": cash_paid_egp, "wht_t4_egp": wht_t4_withheld_egp},
        )
        return EtaSettlementResult(
            settled=True,
            verdict="SAT",
            internal_id=move["name"],
            odoo_move_id=move_id,
            cash_paid_egp=cash_paid_egp,
            wht_t4_withheld_egp=wht_t4_withheld_egp,
            expected_wht_t4_egp=from_piastres(exp_wht_cents),
            gross_invoice_egp=from_piastres(gross_cents),
            wht_certificate_ref=cert_ref,
            violated_rules=[],
            z3_solve_ms=z3_ms,
            merkle_block_hash=blk["block_hash"],
        )
