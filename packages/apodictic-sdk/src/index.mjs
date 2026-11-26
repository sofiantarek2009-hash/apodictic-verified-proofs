/**
 * @apodictic/sdk — Standalone & Remote SymbolicGateway
 * Persistent local Z3 5.4.1 / PostgreSQL AST / WORM / Rollback / Bi-Temporal /
 * 3-Way Match / Indirect Tax enclave client with full remote HTTP gateway parity
 * and Zero-PII local redaction before any cloud egress.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { evaluateOdoo20Call, extractOdoo20Call } from './odoo20_guard.mjs';
import { PGlite, ShadowPostgresVerifier } from './pglite_shadow.mjs';
import {
  compileDiscoveredPolicyIr,
  discoverSchemaFromOdoo,
  discoverSchemaFromPgDsn,
  discoverSchemaFromSql,
} from './schema_discovery.mjs';
import { checkPolicyIrDeadlockWasm, terminateZ3WasmThreads, Z3WasmEnclaveSession } from './z3_wasm_verifier.mjs';

const ZERO_WIDTH_RE = /[\u200B-\u200D\uFEFF\u00AD]/g;

export function validateIbanMod97(candidate) {
  const cleaned = String(candidate || '').replace(/[\s-]+/g, '').toUpperCase();
  if (cleaned.length < 15 || cleaned.length > 34) return false;
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(cleaned)) return false;
  const rearranged = cleaned.slice(4) + cleaned.slice(0, 2) + '00';
  let mod = 0;
  for (const ch of rearranged) {
    const val = ch >= 'A' && ch <= 'Z' ? String(ch.charCodeAt(0) - 55) : ch;
    for (const d of val) {
      mod = (mod * 10 + Number(d)) % 97;
    }
  }
  return String(98 - mod).padStart(2, '0') === cleaned.slice(2, 4);
}

export function validateLuhnPan(candidate) {
  const digits = String(candidate || '').replace(/[\s-]+/g, '');
  if (!/^\d{13,19}$/.test(digits)) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = Number(digits[i]);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum > 0 && sum % 10 === 0;
}

const PATTERNS = [
  { key: 'SECRET', re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g },
  { key: 'SECRET', re: /\b(?:sk_live|sk_test|pk_live|pk_test|rk_live|rk_test|ghp|gho|glpat|xoxb|xoxp|odoo_rpc_live)_[A-Za-z0-9_-]{6,}\b/g },
  { key: 'SECRET', re: /\bAIzaSy[A-Za-z0-9_-]{20,40}\b/g },
  { key: 'SECRET', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { key: 'SECRET', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { key: 'DB_URL', re: /\bpostgres(?:ql)?:\/\/[^\s'"]+@[^\s'"]+\b/gi },
  { key: 'IBAN', re: /\b[A-Za-z]{2}\d{2}(?:[A-Za-z0-9]{10,30}|(?:[\s-][A-Za-z0-9]{4}){2,7}(?:[\s-][A-Za-z0-9]{1,4})?)\b/g },
  { key: 'CARD', re: /\b(?:\d{4}[-\s]?\d{6}[-\s]?\d{5}|\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,7}|\d{13,19})\b/g },
  { key: 'EMAIL', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { key: 'TAX', re: /\b(?:ETA-\d{6,12}|TIN\s*\d{2}-\d{7}|\d{3}-\d{3}-\d{3})\b/g },
  { key: 'QUOTED_LIT', re: /'((?:''|[^']){4,})'/g },
];

const SRC_DIR = path.dirname(fileURLToPath(import.meta.url));
const WORKER_SCRIPT = path.join(SRC_DIR, 'enclave_worker.py');
const DEFAULT_REPO_ROOT = path.resolve(SRC_DIR, '..', '..', '..');

export class SymbolicGateway {
  constructor(options = {}) {
    this.posture = options.posture || (options.airgap ? 'MODE_A_AIRGAP' : 'MODE_B_HYBRID');
    this.airgap = Boolean(options.airgap) || this.posture === 'MODE_A_AIRGAP';
    this.vaultPath = options.vaultPath || 'sqlite:///var/run/apodictic/sym_vault.db';
    this.forbidRawLiterals = options.forbidRawLiterals !== false;
    this.endpoint = this.airgap ? '' : (options.endpoint || process.env.APODICTIC_ENDPOINT || '');
    this.apiKey = options.apiKey || process.env.APODICTIC_API_KEY || '';
    this.repoRoot = options.repoRoot || process.env.APODICTIC_REPO_ROOT || DEFAULT_REPO_ROOT;
    this.pythonBin = options.pythonBin || process.env.APODICTIC_PYTHON || 'python3';
    this.engine = options.engine || 'auto'; // 'auto' | 'python' | 'wasm' | 'rust'
    this.rustKernelPath = options.rustKernelPath || process.env.APODICTIC_RUST_KERNEL || '';
    this.stateDbPath = options.stateDbPath || process.env.APODICTIC_STATE_DB || '';
    this.timeoutMs = options.timeoutMs ?? 15000;

    this.forward = new Map();
    this.sensitiveSecrets = new Map();
    this.quotedLiterals = new Map();
    this.reverse = new Map();
    this.counters = {};

    this._worker = null;
    this._pending = new Map();
    this._nextReqId = 1;
    this._pythonUnavailable = process.env.APODICTIC_DISABLE_PYTHON === '1';

    this._wasmSession = null;

    this._rustWorker = null;
    this._rustPending = new Map();
    this._nextRustReqId = 1;

    this._shadowVerifier = null;
  }

  _mint(prefix, raw) {
    if (this.forward.has(raw)) return this.forward.get(raw);
    const n = (this.counters[prefix] = (this.counters[prefix] || 0) + 1);
    const sym = `<SYM_${prefix}_${String(n).padStart(2, '0')}>`;
    this.forward.set(raw, sym);
    if (prefix === 'LIT') {
      this.quotedLiterals.set(raw, sym);
    } else {
      this.sensitiveSecrets.set(raw, sym);
    }
    this.reverse.set(sym, raw);
    return sym;
  }

  scrubSqlAst(input, opts = {}) {
    const scrubQuotedLiterals = opts?.scrubQuotedLiterals !== false;
    let text = String(input ?? '').replace(ZERO_WIDTH_RE, '');
    let redacted = 0;
    let ibanMod97ValidCount = 0;
    let luhnPanValidCount = 0;
    for (const { key, re } of PATTERNS) {
      if (key === 'QUOTED_LIT' && !scrubQuotedLiterals) continue;
      text = text.replace(re, (match, group1) => {
        if (key === 'CARD') {
          if (!validateLuhnPan(match)) return match;
          luhnPanValidCount++;
        }
        if (key === 'IBAN') {
          if (!validateIbanMod97(match)) return match;
          ibanMod97ValidCount++;
        }
        if (key === 'QUOTED_LIT') {
          if (group1.startsWith('<SYM_') && group1.endsWith('>')) return match;
          const sym = this._mint('LIT', group1);
          redacted++;
          return `'${sym}'`;
        }
        redacted++;
        return this._mint(key, match);
      });
    }
    if (this.forbidRawLiterals) {
      const checkMap = scrubQuotedLiterals ? this.forward : this.sensitiveSecrets;
      for (const raw of checkMap.keys()) {
        if (text.includes(raw)) {
          throw new Error('Strict egress violation: literal remained unmasked');
        }
      }
    }
    return {
      sanitized: text,
      redactions: redacted,
      symbolCount: this.forward.size,
      dlpChecksums: {
        ibanMod97ValidCount,
        luhnPanValidCount,
        validators: ['ISO-7064-Mod-97-10', 'Luhn-Mod-10'],
      },
    };
  }

  rehydrate(text) {
    let out = String(text ?? '');
    const entries = [...this.reverse.entries()].reverse();
    for (let pass = 0; pass < 3; pass++) {
      let changed = false;
      for (const [sym, raw] of entries) {
        if (out.includes(sym)) {
          out = out.split(sym).join(raw);
          changed = true;
        }
      }
      if (!changed) break;
    }
    return out;
  }

  _getWasmSession() {
    if (!this._wasmSession) {
      this._wasmSession = new Z3WasmEnclaveSession(this.stateDbPath);
    }
    return this._wasmSession;
  }

  async _dispatchWasm(method, params = {}) {
    const sess = this._getWasmSession();
    if (method === 'verify_mutation') return await sess.verifyMutation(params);
    if (method === 'rollback') return sess.rollback(params);
    if (method === 'flush_escrow') return sess.flushEscrow(params);
    if (method === 'verify_three_way_match') return await sess.verifyThreeWayMatch(params);
    if (method === 'verify_tax_compliance') return await sess.verifyTaxCompliance(params);
    if (method === 'evaluate_policy') return await sess.evaluatePolicy(params);
    if (method === 'bitemporal_insert') return sess.bitemporalInsert(params);
    if (method === 'bitemporal_restate') return sess.bitemporalRestate(params);
    if (method === 'bitemporal_as_of') return sess.bitemporalAsOf(params);
    if (method === 'verify_audit_chain') return sess.verifyAuditChain();
    if (method === 'merkle_inclusion_proof') return sess.generateRfc6962InclusionProof(params?.blockIndex);
    if (method === 'health') return sess.health();
    throw new Error(`Unsupported WASM enclave method: ${method}`);
  }

  _ensureWorker() {
    if (this._worker && !this._worker.killed) return this._worker;
    if (!fs.existsSync(WORKER_SCRIPT)) {
      throw new Error(`Apodictic worker script missing at ${WORKER_SCRIPT}`);
    }

    const hasMonorepo = fs.existsSync(path.join(this.repoRoot, 'apodictic_engine', 'src', 'proxy', 'interceptor.py'));
    const env = { ...process.env };
    if (hasMonorepo) env.PYTHONPATH = this.repoRoot;
    if (this.stateDbPath) env.APODICTIC_STATE_DB = this.stateDbPath;
    if (this.airgap) env.APODICTIC_AIRGAP = '1';

    const child = spawn(this.pythonBin, ['-B', WORKER_SCRIPT], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env,
    });

    let stderrBuf = '';
    child.stderr.on('data', (chunk) => {
      stderrBuf = (stderrBuf + chunk.toString()).slice(-2048);
    });

    const rejectAllPending = (errMsg) => {
      for (const [, entry] of this._pending) {
        clearTimeout(entry.timer);
        entry.reject(new Error(errMsg));
      }
      this._pending.clear();
      this._worker = null;
    };

    child.on('error', (err) => {
      this._pythonUnavailable = true;
      rejectAllPending(`Apodictic Python worker unavailable (${err.code || err.message})`);
    });
    child.stdin.on('error', () => {
      // Handled via child error/exit handlers
    });

    const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
    rl.on('line', (line) => {
      try {
        const msg = JSON.parse(line);
        const entry = this._pending.get(msg.id);
        if (!entry) return;
        clearTimeout(entry.timer);
        this._pending.delete(msg.id);
        if (msg.error) entry.reject(new Error(msg.error.message || 'Enclave error'));
        else entry.resolve(msg.result);
      } catch {
        // Ignore non-JSON stderr/debug noise
      }
    });

    child.on('exit', (code) => {
      if (code === 2 || stderrBuf.includes('z3-solver not found')) {
        this._pythonUnavailable = true;
      }
      const detail = stderrBuf.trim();
      const errMsg = detail
        ? `Apodictic enclave worker exited unexpectedly: ${detail}`
        : `Apodictic enclave worker exited unexpectedly (code ${code ?? 'unknown'})`;
      rejectAllPending(errMsg);
    });

    this._worker = child;
    return child;
  }

  _callWorker(method, params = {}) {
    const child = this._ensureWorker();
    const id = this._nextReqId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(id);
        reject(new Error(`Apodictic enclave call '${method}' timed out after ${this.timeoutMs}ms`));
      }, this.timeoutMs);
      this._pending.set(id, { resolve, reject, timer });
      try {
        child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
      } catch (err) {
        clearTimeout(timer);
        this._pending.delete(id);
        reject(err);
      }
    });
  }

  async _callRemote(method, params = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (this.apiKey) headers.Authorization = `Bearer ${this.apiKey}`;
    const targetUrl = this.endpoint.endsWith('/api/v1/enclave')
      ? this.endpoint
      : `${this.endpoint.replace(/\/+$/, '')}`;
    const body = targetUrl.includes('/api/apodictic/verify') && method === 'verify_mutation'
      ? {
          payload: params.sql,
          action: params.action,
          amount: params.amount ?? 0,
          currentBalance: params.currentBalance,
          minReserve: params.minReserve,
          maxAutonomousLimit: params.maxAutonomousLimit,
          cfoApproved: params.cfoSigned,
          vatRate: params.statutoryVat,
          expectedVatRate: params.expectedVat,
          targetSystem: params.targetSystem,
        }
      : { method, params };

    const res = await fetch(targetUrl, {
      method: 'POST',
      headers,
      signal: AbortSignal.timeout(this.timeoutMs),
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      throw new Error(`Apodictic gateway returned HTTP ${res.status}`);
    }
    const data = await res.json();
    if (data.error) {
      throw new Error(data.error.message || String(data.error));
    }
    return data.result ?? data;
  }

  async _dispatch(method, params = {}) {
    if (this.endpoint && !this.airgap) {
      return this._callRemote(method, params);
    }
    if (this.engine === 'wasm' || this._pythonUnavailable) {
      return this._dispatchWasm(method, params);
    }
    try {
      return await this._callWorker(method, params);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const isEnvUnavailable =
        this._pythonUnavailable ||
        msg.includes('ENOENT') ||
        msg.includes('z3-solver not found') ||
        msg.includes('worker unavailable');
      if (this.engine === 'auto' && isEnvUnavailable) {
        this._pythonUnavailable = true;
        return this._dispatchWasm(method, params);
      }
      throw err;
    }
  }

  _resolveRustKernelPath() {
    const cands = [
      this.rustKernelPath,
      path.join(this.repoRoot, 'apodictic_infra', 'target', 'release', 'apodictic_rust_kernel'),
      path.join(this.repoRoot, 'apodictic_infra', 'target', 'debug', 'apodictic_rust_kernel'),
    ].filter(Boolean);
    for (const c of cands) {
      if (fs.existsSync(c)) return c;
    }
    return '';
  }

  _ensureRustWorker() {
    if (this._rustWorker && !this._rustWorker.killed) return this._rustWorker;
    const binPath = this._resolveRustKernelPath();
    if (!binPath) {
      throw new Error('Native apodictic_rust_kernel binary not found in apodictic_infra/target');
    }
    const child = spawn(binPath, ['--daemon'], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const rejectRustPending = (msg) => {
      for (const [, entry] of this._rustPending) {
        clearTimeout(entry.timer);
        entry.reject(new Error(msg));
      }
      this._rustPending.clear();
      this._rustWorker = null;
    };
    child.on('error', (err) => {
      rejectRustPending(`Apodictic Rust daemon failed to spawn (${err.code || err.message})`);
    });
    child.stdin.on('error', () => {
      // Handled via error/exit events
    });
    const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
    rl.on('line', (line) => {
      try {
        const msg = JSON.parse(line);
        const entry = this._rustPending.get(Number(msg.id));
        if (!entry) return;
        clearTimeout(entry.timer);
        this._rustPending.delete(Number(msg.id));
        if (msg.error) entry.reject(new Error(String(msg.error)));
        else entry.resolve(msg.result ?? msg);
      } catch {
        // ignore non-JSON debug output
      }
    });
    child.on('exit', () => {
      rejectRustPending('Apodictic Rust daemon exited unexpectedly');
    });
    this._rustWorker = child;
    return child;
  }

  _callRustWorker(params = {}) {
    const child = this._ensureRustWorker();
    const id = this._nextRustReqId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._rustPending.delete(id);
        reject(new Error(`Apodictic Rust daemon timed out after ${this.timeoutMs}ms`));
      }, this.timeoutMs);
      this._rustPending.set(id, { resolve, reject, timer });
      child.stdin.write(JSON.stringify({ id, params }) + '\n');
    });
  }

  async verifyMutationNativeRust(input = {}) {
    if (input.amount !== undefined && (!Number.isFinite(Number(input.amount)) || Number(input.amount) < 0)) {
      throw new Error('Invalid mutation amount: must be a non-negative finite number');
    }
    const rawSql = String(input.sql || '').replace(ZERO_WIDTH_RE, '');
    const r = await this._callRustWorker({
      sql: rawSql,
      account: input.accountId || 'sdk_default',
      amount: input.amount ?? 0,
      current_balance: input.currentBalance ?? 250000,
      min_reserve: input.minReserve ?? 50000,
      spending_limit: input.maxAutonomousLimit ?? 50000,
      cfo_signed: Boolean(input.cfoSigned),
      pgoutput_hex: input.pgoutputHex || undefined,
    });
    const ast = r.rust_sql_ast || {};
    const z3 = r.libz3_c_ffi_proof || {};
    const hasZ3 = Boolean(z3 && typeof z3.verdict === 'string' && z3.ffi_linked !== false);
    const astBlocked = Boolean(ast.is_unbounded || ast.has_multi_statement || ['DROP', 'TRUNCATE', 'DELETE', 'ALTER'].includes(String(ast.statement_type || '').toUpperCase()));
    const verified = !astBlocked && hasZ3 && z3.verdict === 'SAT';
    const failReason = astBlocked
      ? `UNBOUNDED_OR_DESTRUCTIVE_${ast.statement_type || 'SQL'}`
      : !hasZ3
        ? 'Z3_FFI_UNLINKED_FAIL_CLOSED'
        : (z3.unsat_core?.[0] || 'INV_LIBZ3_UNSAT');
    const pseudonymCount = r.pseudonym_map ? Object.keys(r.pseudonym_map).length : 0;
    const totalUs = r.timings_us?.total_rust_kernel_us ?? 0;
    const solveUs = r.timings_us?.libz3_c_ffi_solve_us ?? z3.solve_us ?? 0;

    return {
      verdict: verified ? 'SAT' : 'UNSAT',
      verified,
      engine: 'apodictic-rust-daemon-libz3-ffi',
      proofId: `rust_worm_${r.worm_sequence_num ?? 1}`,
      proofDigest: z3.proof_digest_sha256 || r.merkle_state_root,
      blockIndex: r.worm_sequence_num,
      merkleStateRoot: r.merkle_state_root,
      rfc6962LeafHash: r.rfc6962_leaf_hash ?? null,
      rfc6962AuditPath: r.rfc6962_audit_path ?? [],
      pseudonymMap: r.pseudonym_map ?? {},
      pgoutputDecoded: r.pgoutput_decoded ?? null,
      z3SolveMs: Number((Number(solveUs) / 1000).toFixed(4)),
      totalLatencyMs: Number((Number(totalUs) / 1000).toFixed(4)),
      redactions: pseudonymCount,
      sanitizedSql: r.sanitized_sql || rawSql,
      unsatCore: verified ? [] : (z3.unsat_core || []),
      reason: verified ? null : failReason,
    };
  }

  async verifyMutation(input = {}) {
    if (
      !this.endpoint &&
      (input.engine === 'rust' || (this.engine === 'rust' && input.engine !== 'python' && input.engine !== 'wasm'))
    ) {
      return this.verifyMutationNativeRust(input);
    }
    if (input.amount !== undefined && (!Number.isFinite(Number(input.amount)) || Number(input.amount) < 0)) {
      throw new Error('Invalid mutation amount: must be a non-negative finite number');
    }

    const rawSql = String(input.sql || '').replace(ZERO_WIDTH_RE, '');
    const scrubbed = this.scrubSqlAst(rawSql);
    const hasExplicitCurrentBalance = input.currentBalance !== undefined && input.currentBalance !== null;
    const odooEval = evaluateOdoo20Call(input);

    const payload = {
      sql: this.endpoint ? scrubbed.sanitized : rawSql,
      action: input.action || 'MUTATION',
      accountId: input.accountId || 'sdk_default',
      amount: input.amount,
      currentBalance: input.currentBalance ?? 250000,
      hasExplicitCurrentBalance,
      stateless: Boolean(input.stateless),
      minReserve: input.minReserve ?? 50000,
      maxAutonomousLimit: input.maxAutonomousLimit ?? 50000,
      cfoSigned: Boolean(input.cfoSigned),
      debitTotal: input.debitTotal !== undefined ? Number(input.debitTotal) : odooEval.lineChecks?.debitTotal,
      creditTotal: input.creditTotal !== undefined ? Number(input.creditTotal) : odooEval.lineChecks?.creditTotal,
      statutoryVat: input.statutoryVat ?? 0.14,
      expectedVat: input.expectedVat ?? 0.14,
      targetSystem: input.targetSystem || (odooEval.isOdooCall ? 'odoo_v20' : 'postgresql'),
      odoo: input.odoo,
    };

    const data = input.engine === 'wasm'
      ? await this._dispatchWasm('verify_mutation', payload)
      : await this._dispatch('verify_mutation', payload);

    // Fail-closed intersection: if Odoo 20 structural/scope/lock guard flagged violations even when backed by Python/HTTP, block immediately
    const odooViolations = odooEval.violations || [];
    const verified = Boolean(data.verified) && odooViolations.length === 0;
    const verdict = verified ? (data.verdict || 'SAT') : 'UNSAT';
    return {
      verdict,
      verified,
      engine: this.endpoint ? (data.engine || 'apodictic-http-gateway-z3-5.4.1') : (data.engine || 'apodictic-local-z3-5.4.1'),
      proofId: data.proof_id,
      proofDigest: data.proof_digest || data.proof_hash,
      blockIndex: data.block_index,
      blockHash: data.block_hash,
      rollbackBatchId: data.rollback_batch_id ?? null,
      escrowStatus: verified ? (data.escrow_status ?? null) : 'VETOED_PRE_COMMIT',
      doubleEntryAccount: data.double_entry_account ?? null,
      walBeforeImage: data.wal_before_image ?? null,
      rfc6962LeafHash: data.rfc6962_leaf_hash ?? null,
      rfc6962TreeRoot: data.rfc6962_tree_root ?? null,
      dlpChecksums: data.dlp_checksums ?? null,
      odoo20Evaluation: odooEval.isOdooCall ? odooEval : undefined,
      z3SolveMs: data.timings?.z3_solve_ms ?? data.z3_solve_ms,
      totalLatencyMs: data.timings?.total_proxy_latency_ms ?? data.execution_time_ms,
      redactions: this.endpoint ? Math.max(scrubbed.redactions, data.pii_entities_redacted ?? data.redactions ?? 0) : (data.redactions ?? 0),
      sanitizedSql: data.sanitized_sql || data.tokenized_payload || scrubbed.sanitized,
      counterfactualPatch: verified ? null : (data.counterfactual_patch ?? data.counterfactualPatch ?? null),
      reason: verified
        ? null
        : (odooViolations[0] || data.violation_reason || data.violated_invariants?.[0] || data.unsat_core?.[0] || `INV_Z3_UNSAT (${data.ast_analysis?.statement_type || 'MUTATION'})`),
    };
  }

  async shadowExecuteAndProve(input = {}) {
    if (!this._shadowVerifier) {
      this._shadowVerifier = new ShadowPostgresVerifier(this);
    }
    return this._shadowVerifier.shadowExecuteAndProve(input);
  }

  verifySql(sql, options = {}) {
    return this.verifyMutation({ ...options, sql });
  }

  rollback(batchId) {
    return this._dispatch('rollback', { batchId });
  }

  verifyThreeWayMatch(input) {
    return this._dispatch('verify_three_way_match', input);
  }

  verifyTaxCompliance(input) {
    return this._dispatch('verify_tax_compliance', input);
  }

  bitemporalInsert(input) {
    return this._dispatch('bitemporal_insert', input);
  }

  bitemporalRestate(input) {
    return this._dispatch('bitemporal_restate', input);
  }

  bitemporalAsOf(input) {
    return this._dispatch('bitemporal_as_of', input);
  }

  verifyAuditChain() {
    return this._dispatch('verify_audit_chain', {});
  }

  flushEscrow(options = {}) {
    return this._dispatch('flush_escrow', options);
  }

  evaluatePolicy(options = {}) {
    return this._dispatch('evaluate_policy', options);
  }

  getMerkleInclusionProof(blockIndex) {
    return this._dispatch('merkle_inclusion_proof', blockIndex !== undefined ? { blockIndex } : {});
  }

  health() {
    return this._dispatch('health', {});
  }

  async close() {
    if (this._shadowVerifier) {
      await this._shadowVerifier.close();
      this._shadowVerifier = null;
    }
    if (this._wasmSession) {
      this._wasmSession.close();
      this._wasmSession = null;
    } else {
      terminateZ3WasmThreads();
    }
    if (this._worker && !this._worker.killed) {
      this._worker.stdin.end();
      this._worker.kill();
      this._worker = null;
    }
    if (this._rustWorker && !this._rustWorker.killed) {
      this._rustWorker.stdin.end();
      this._rustWorker.kill();
      this._rustWorker = null;
    }
  }
}

export {
  PGlite,
  ShadowPostgresVerifier,
  Z3WasmEnclaveSession,
  checkPolicyIrDeadlockWasm,
  compileDiscoveredPolicyIr,
  discoverSchemaFromOdoo,
  discoverSchemaFromPgDsn,
  discoverSchemaFromSql,
  evaluateOdoo20Call,
  extractOdoo20Call,
};
export default SymbolicGateway;
