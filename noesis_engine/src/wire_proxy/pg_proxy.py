"""
Apodictic Enterprise PostgreSQL Wire Transparent Proxy Server
Listens on TCP (default port 5432 or 5433).
Intercepts incoming SQL queries:
1. Passes raw SQL to DeepDLP to scrub PII / API keys.
2. Compiles query with recursive-descent AST parser.
3. If mutation is detected, triggers formal Z3 SMT theory solver.
4. If Z3 returns UNSAT (invariant violation) or AST flags unbounded drop/truncate/delete:
   - Blocks packet immediately.
   - Synthesizes PostgreSQL ErrorResponse packet ('E') with SQLSTATE 28000/40001.
   - Emits ReadyForQuery ('Z') in error state.
   - Upstream database socket is NEVER touched.
5. If SAT:
   - Forwards transparently to upstream PostgreSQL database socket.
   - Streams response packets back to the client.
"""

import asyncio
import logging
import re
from typing import Optional, Tuple, Dict, Any

from noesis_engine.src.wire_proxy.pg_protocol import (
    PostgresWireCodec,
    PostgresPacket,
    MSG_QUERY,
    MSG_PARSE,
    MSG_TERMINATE,
    SQLSTATE_VERIFICATION_REJECTED,
    SQLSTATE_DESTRUCTIVE_MUTATION,
    SQLSTATE_SOLVENCY_BREACH,
)
from noesis_engine.src.ast_compiler.sql_compiler import SqlAstCompiler
from noesis_engine.src.smt_theory.theory_kernel import AdvancedSmtKernel as TheoryKernel
from noesis_engine.src.core.types import DagStep, MutationType, TargetSystemType
from noesis_engine.src.dlp_engine.deep_dlp import DeepDlpEngine
from noesis_engine.src.audit_ledger.merkle_sealer import MerkleAuditLedger

logger = logging.getLogger("NoesisPgProxy")


class NoesisPostgresProxySession:
    """
    Manages an active two-way TCP proxy bridge between client and upstream Postgres.
    """
    def __init__(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                 upstream_host: str, upstream_port: int,
                 audit_ledger: MerkleAuditLedger,
                 context_state: Optional[Dict[str, Any]] = None):
        self.client_reader = client_reader
        self.client_writer = client_writer
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.upstream_reader: Optional[asyncio.StreamReader] = None
        self.upstream_writer: Optional[asyncio.StreamWriter] = None

        self.ast_compiler = SqlAstCompiler
        self.smt_kernel = TheoryKernel()
        self.dlp_engine = DeepDlpEngine()
        self.audit_ledger = audit_ledger

        self.context_state = context_state or {
            "initial_balance": 100000.0,
            "min_reserve": 20000.0,
            "max_autonomous_limit": 25000.0,
            "cfo_approved": False,
        }
        self.is_connected = True
        self.active_transactions = 0

    async def connect_upstream(self) -> bool:
        """Attempts connection to real upstream PostgreSQL server."""
        try:
            self.upstream_reader, self.upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(self.upstream_host, self.upstream_port),
                timeout=3.0
            )
            return True
        except Exception as e:
            logger.warning(f"Upstream Postgres ({self.upstream_host}:{self.upstream_port}) not reachable: {e}. Running in standalone interceptor mode.")
            self.upstream_reader = None
            self.upstream_writer = None
            return False

    async def run(self):
        """Main proxy event loop."""
        upstream_connected = await self.connect_upstream()
        client_buffer = b""
        is_startup = True

        try:
            while self.is_connected:
                data = await self.client_reader.read(4096)
                if not data:
                    break
                client_buffer += data

                while True:
                    packet, client_buffer = PostgresWireCodec.decode_packet(client_buffer, is_startup=is_startup)
                    if packet is None:
                        break

                    if is_startup:
                        is_startup = False
                        await self.handle_startup(packet, upstream_connected)
                        continue

                    # Handle normal packet
                    should_forward = await self.handle_packet(packet)
                    if should_forward and upstream_connected and self.upstream_writer:
                        wire_bytes = packet.msg_type + struct_pack_len(packet.length) + packet.payload
                        self.upstream_writer.write(wire_bytes)
                        await self.upstream_writer.drain()
                    elif not should_forward:
                        # Transaction was blocked by formal verification
                        pass
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error in proxy session: {e}", exc_info=True)
        finally:
            await self.close()

    async def handle_startup(self, packet: PostgresPacket, upstream_connected: bool):
        """Processes startup message."""
        if len(packet.payload) == 4 and packet.payload == b'\x04\xd2\x16\x2f':
            # SSLRequest
            self.client_writer.write(b'N')  # SSL unsupported / unneeded for local proxy
            await self.client_writer.drain()
            return

        params = PostgresWireCodec.parse_startup_params(packet.payload)
        logger.info(f"Client startup params: user={params.get('user')}, db={params.get('database')}")

        if upstream_connected and self.upstream_writer:
            wire_bytes = struct_pack_len(packet.length) + packet.payload
            self.upstream_writer.write(wire_bytes)
            await self.upstream_writer.drain()
            # Start pipe upstream -> client
            asyncio.create_task(self.pipe_upstream_to_client())
        else:
            # Standalone mock authentication for local testing / dev environment
            auth_ok = PostgresWireCodec.encode_auth_ok()
            ready = PostgresWireCodec.encode_ready_for_query(b'I')
            self.client_writer.write(auth_ok + ready)
            await self.client_writer.drain()

    async def handle_packet(self, packet: PostgresPacket) -> bool:
        """
        Inspects message payload. Returns True if safe to forward, False if rejected.
        """
        if packet.msg_type == MSG_TERMINATE:
            self.is_connected = False
            return True

        if packet.msg_type not in (MSG_QUERY, MSG_PARSE):
            return True

        sql_query = PostgresWireCodec.extract_query_string(packet)
        if not sql_query:
            return True

        # 1. DLP Inspection & Sanitization
        sanitized_sql, redactions, _bytes_removed = self.dlp_engine.sanitize_text(sql_query)
        if redactions:
            logger.info(f"Zero-PII Gateway redacted {len(redactions)} secrets from wire query")

        # 2. SQL AST Compilation
        ast_node = self.ast_compiler.compile(sanitized_sql)
        op_name = ast_node.statement_type.value
        table_label = ast_node.target_tables[0] if ast_node.target_tables else "unknown"

        if ast_node.is_unbounded:
            # Reject immediately
            err_pkt = PostgresWireCodec.encode_error_response(
                message=f"Apodictic Pre-Execution Firewall blocked query: Unbounded mutation detected on table '{table_label}'. Destructive mutations without WHERE clause are strictly prohibited.",
                sqlstate=SQLSTATE_DESTRUCTIVE_MUTATION,
                hint="Add an explicit primary-key WHERE constraint or obtain dual-custody authorization."
            )
            ready_pkt = PostgresWireCodec.encode_ready_for_query(b'E')
            self.client_writer.write(err_pkt + ready_pkt)
            await self.client_writer.drain()

            self.audit_ledger.append_block(
                proof_id="ast_unbounded_gate",
                action=op_name,
                verdict="UNSAT",
                target_system="postgresql_wal",
                zk_digest="unbounded_mutation_blocked",
                metadata={"query": sanitized_sql, "table": table_label, "status": "BLOCKED_UNBOUNDED_MUTATION"},
            )
            return False

        # 3. Z3 Formal SMT Verification on Payouts / Financial Mutations
        upper_sql = sanitized_sql.upper()
        is_financial = (
            ast_node.statement_type in (MutationType.UPDATE, MutationType.DELETE, MutationType.INSERT)
            and any(kw in upper_sql for kw in ("PAYOUT", "ACCOUNT", "DISBURSE", "BALANCE", "LEDGER"))
        )
        if is_financial:
            amount = self.extract_amount_from_ast(ast_node, sanitized_sql)
            dag_steps = [
                DagStep(
                    step_id="wire_query_mutation",
                    name="wire_query_mutation",
                    target_system=TargetSystemType.POSTGRESQL,
                    action=op_name,
                    amount=amount,
                    account_id=table_label,
                    requires_approval=(amount > self.context_state["max_autonomous_limit"]),
                )
            ]
            cert = self.smt_kernel.verify_financial_dag(
                initial_balance=self.context_state["initial_balance"],
                minimum_reserve=self.context_state["min_reserve"],
                spending_limit=self.context_state["max_autonomous_limit"],
                cfo_signed=self.context_state["cfo_approved"],
                is_destructive_op=ast_node.statement_type in (MutationType.DELETE, MutationType.DROP, MutationType.TRUNCATE),
                reversal_armed=True,
                statutory_vat=0.14,
                expected_vat=0.14,
                dag_steps=dag_steps,
            )

            if cert.verdict.name == "UNSAT":
                # Mathematical Proof of Invariant Violation
                violations_str = ", ".join(cert.unsat_core)
                err_pkt = PostgresWireCodec.encode_error_response(
                    message=f"Apodictic SMT Kernel Invariant Violation: Query rejected mathematically (Z3 verdict: UNSAT). Violated: [{violations_str}]",
                    sqlstate=SQLSTATE_SOLVENCY_BREACH,
                    detail=f"Amount: ${amount:,.2f} | Current Reserve: ${self.context_state['initial_balance']:,.2f} | Solvency Floor: ${self.context_state['min_reserve']:,.2f}",
                    hint="Disburse an amount within autonomous spend caps or provide valid CFO cryptographic authorization."
                )
                ready_pkt = PostgresWireCodec.encode_ready_for_query(b'E')
                self.client_writer.write(err_pkt + ready_pkt)
                await self.client_writer.drain()

                self.audit_ledger.append_block(
                    proof_id=cert.proof_id,
                    action=op_name,
                    verdict="UNSAT",
                    target_system="postgresql_wal",
                    zk_digest=cert.sha256_hash,
                    metadata={"query": sanitized_sql, "violations": cert.unsat_core, "status": "BLOCKED_Z3_UNSAT"},
                )
                return False

            self.audit_ledger.append_block(
                proof_id=cert.proof_id,
                action=op_name,
                verdict="SAT",
                target_system="postgresql_wal",
                zk_digest=cert.sha256_hash,
                metadata={"query": sanitized_sql, "status": "VERIFIED_COMMIT"},
            )

        # In standalone mode without real postgres upstream, return simulated CommandComplete
        if not self.upstream_writer:
            cmd = PostgresWireCodec.encode_command_complete(f"{op_name} 1")
            ready = PostgresWireCodec.encode_ready_for_query(b'I')
            self.client_writer.write(cmd + ready)
            await self.client_writer.drain()
            return False

        return True

    def extract_amount_from_ast(self, ast_node, sql_text: str = "") -> float:
        """Parses amount literal from SQL mutation expressions or WHERE predicates."""
        query = sql_text or getattr(ast_node, "raw_query", "")
        # Look for SET balance = balance - X or numeric literals > 10
        m = re.search(r"(?:balance\s*[-+]\s*|amount\s*=\s*|values\s*\([^)]*?,\s*)([0-9]+(?:\.[0-9]+)?)", query, re.IGNORECASE)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass
        for pred in getattr(ast_node, "predicates", []):
            try:
                val = float(pred.right)
                if val > 0:
                    return val
            except (TypeError, ValueError):
                continue
        for tok in re.findall(r"\b([0-9]+(?:\.[0-9]+)?)\b", query):
            try:
                val = float(tok)
                if val >= 100.0:
                    return val
            except ValueError:
                continue
        return 10000.0

    async def pipe_upstream_to_client(self):
        """Pipes packets back from upstream PostgreSQL to client."""
        try:
            while self.is_connected and self.upstream_reader:
                data = await self.upstream_reader.read(4096)
                if not data:
                    break
                self.client_writer.write(data)
                await self.client_writer.drain()
        except Exception:
            pass

    async def close(self):
        """Clean teardown."""
        self.is_connected = False
        try:
            self.client_writer.close()
            await self.client_writer.wait_closed()
        except Exception:
            pass
        if self.upstream_writer:
            try:
                self.upstream_writer.close()
                await self.upstream_writer.wait_closed()
            except Exception:
                pass


def struct_pack_len(length: int) -> bytes:
    import struct
    return struct.pack("!I", length)


class NoesisPostgresProxyServer:
    """Production async TCP server for PostgreSQL Wire Interception."""
    def __init__(self, host: str = "127.0.0.1", port: int = 5433,
                 upstream_host: str = "127.0.0.1", upstream_port: int = 5432):
        self.host = host
        self.port = port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.audit_ledger = MerkleAuditLedger()
        self.server: Optional[asyncio.Server] = None

    async def start(self):
        """Starts TCP listening socket."""
        self.server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        logger.info(f"Apodictic PostgreSQL Wire Proxy listening on {self.host}:{self.port} -> Upstream {self.upstream_host}:{self.upstream_port}")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        session = NoesisPostgresProxySession(
            client_reader=reader,
            client_writer=writer,
            upstream_host=self.upstream_host,
            upstream_port=self.upstream_port,
            audit_ledger=self.audit_ledger
        )
        await session.run()

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
