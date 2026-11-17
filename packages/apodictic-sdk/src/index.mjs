/**
 * @apodictic/sdk — Production SymbolicGateway
 * Persistent local Z3 5.4.1 / PostgreSQL AST / WORM / Rollback / Bi-Temporal /
 * 3-Way Match / Indirect Tax enclave client with optional remote HTTP gateway mode.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const ZERO_WIDTH_RE = /[\u200B-\u200D\uFEFF\u00AD]/g;

const PATTERNS = [
  { key: 'SECRET', re: /\b(?:sk_live|sk_test|pk_live|ghp|xoxb)_[A-Za-z0-9]{8,}\b/g },
  { key: 'IBAN', re: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,26}\b/g },
  { key: 'EMAIL', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { key: 'TAX', re: /\b(?:ETA-\d{6,12}|\d{3}-\d{3}-\d{3})\b/g },
  { key: 'QUOTED_LIT', re: /'([^']{4,})'/g },
];

const SRC_DIR = path.dirname(fileURLToPath(import.meta.url));
const WORKER_SCRIPT = path.join(SRC_DIR, 'enclave_worker.py');
const DEFAULT_REPO_ROOT = path.resolve(SRC_DIR, '..', '..', '..');

export class SymbolicGateway {
  constructor(options = {}) {
    this.posture = options.posture || 'MODE_B_HYBRID';
    this.vaultPath = options.vaultPath || 'sqlite:///var/run/apodictic/sym_vault.db';
    this.forbidRawLiterals = options.forbidRawLiterals !== false;
    this.endpoint = options.endpoint || process.env.APODICTIC_ENDPOINT || '';
    this.apiKey = options.apiKey || process.env.APODICTIC_API_KEY || '';
    this.repoRoot = options.repoRoot || process.env.APODICTIC_REPO_ROOT || DEFAULT_REPO_ROOT;
    this.pythonBin = options.pythonBin || process.env.APODICTIC_PYTHON || 'python3';
    this.stateDbPath = options.stateDbPath || process.env.APODICTIC_STATE_DB || '';
    this.timeoutMs = options.timeoutMs ?? 10000;

    this.forward = new Map();
    this.reverse = new Map();
    this.counters = {};

    this._worker = null;
    this._pending = new Map();
    this._nextReqId = 1;
  }

  _mint(prefix, raw) {
    if (this.forward.has(raw)) return this.forward.get(raw);
    const n = (this.counters[prefix] = (this.counters[prefix] || 0) + 1);
    const sym = `<SYM_${prefix}_${String(n).padStart(2, '0')}>`;
    this.forward.set(raw, sym);
    this.reverse.set(sym, raw);
    return sym;
  }

  scrubSqlAst(input) {
    // Strip zero-width evasion chars before pattern matching
    let text = String(input ?? '').replace(ZERO_WIDTH_RE, '');
    let redacted = 0;
    for (const { key, re } of PATTERNS) {
      text = text.replace(re, (match, group1) => {
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
      for (const raw of this.forward.keys()) {
        if (text.includes(raw)) {
          throw new Error('Strict egress violation: literal remained unmasked');
        }
      }
    }
    return { sanitized: text, redactions: redacted, symbolCount: this.forward.size };
  }

  rehydrate(text) {
    let out = String(text ?? '');
    for (const [sym, raw] of this.reverse.entries()) {
      out = out.split(sym).join(raw);
    }
    return out;
  }

  _ensureWorker() {
    if (this._worker && !this._worker.killed) return this._worker;
    if (!fs.existsSync(path.join(this.repoRoot, 'noesis_engine', 'src', 'proxy', 'interceptor.py'))) {
      throw new Error('Local noesis_engine enclave not found; pass { endpoint } for remote Apodictic verification.');
    }

    const env = { ...process.env, PYTHONPATH: this.repoRoot };
    if (this.stateDbPath) env.APODICTIC_STATE_DB = this.stateDbPath;
    const child = spawn(this.pythonBin, [WORKER_SCRIPT], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env,
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
        // Ignore non-JSON stderr/debug noise if any
      }
    });

    child.on('exit', () => {
      for (const [, entry] of this._pending) {
        clearTimeout(entry.timer);
        entry.reject(new Error('Apodictic enclave worker exited unexpectedly'));
      }
      this._pending.clear();
      this._worker = null;
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
      child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
    });
  }

  async verifyMutation(input = {}) {
    if (input.amount !== undefined && (!Number.isFinite(Number(input.amount)) || Number(input.amount) < 0)) {
      throw new Error('Invalid mutation amount: must be a non-negative finite number');
    }

    const normalizedSql = String(input.sql || '').replace(ZERO_WIDTH_RE, '');
    const payload = {
      sql: normalizedSql,
      action: input.action || 'MUTATION',
      accountId: input.accountId || 'sdk_default',
      amount: input.amount,
      currentBalance: input.currentBalance ?? 250000,
      minReserve: input.minReserve ?? 50000,
      maxAutonomousLimit: input.maxAutonomousLimit ?? 50000,
      cfoSigned: Boolean(input.cfoSigned),
      statutoryVat: input.statutoryVat ?? 0.14,
      expectedVat: input.expectedVat ?? 0.14,
      targetSystem: input.targetSystem || 'postgresql',
    };

    if (this.endpoint) {
      const headers = { 'Content-Type': 'application/json' };
      if (this.apiKey) headers.Authorization = `Bearer ${this.apiKey}`;
      const res = await fetch(this.endpoint, {
        method: 'POST',
        headers,
        signal: AbortSignal.timeout(this.timeoutMs),
        body: JSON.stringify({
          payload: payload.sql,
          action: payload.action,
          amount: payload.amount ?? 0,
          currentBalance: payload.currentBalance,
          minReserve: payload.minReserve,
          maxAutonomousLimit: payload.maxAutonomousLimit,
          cfoApproved: payload.cfoSigned,
          vatRate: payload.statutoryVat,
          expectedVatRate: payload.expectedVat,
          targetSystem: payload.targetSystem,
        }),
      });
      if (!res.ok) throw new Error(`Apodictic gateway returned HTTP ${res.status}`);
      const data = await res.json();
      return {
        verdict: data.verdict,
        verified: Boolean(data.verified),
        engine: data.engine || 'apodictic-http-gateway-z3-5.4.1',
        proofDigest: data.proof_hash,
        z3SolveMs: data.z3_solve_ms,
        redactions: data.pii_entities_redacted ?? 0,
        sanitizedSql: data.tokenized_payload || payload.sql,
        reason: data.verified ? null : (data.violated_invariants?.[0] || 'INVARIANT_VIOLATION'),
      };
    }

    const data = await this._callWorker('verify_mutation', payload);
    return {
      verdict: data.verdict,
      verified: Boolean(data.verified),
      engine: 'apodictic-local-z3-5.4.1',
      proofId: data.proof_id,
      proofDigest: data.proof_digest,
      blockIndex: data.block_index,
      blockHash: data.block_hash,
      rollbackBatchId: data.rollback_batch_id ?? null,
      z3SolveMs: data.timings?.z3_solve_ms,
      totalLatencyMs: data.timings?.total_proxy_latency_ms,
      redactions: data.redactions ?? 0,
      sanitizedSql: data.sanitized_sql || payload.sql,
      reason: data.verified ? null : `INV_Z3_UNSAT (${data.ast_analysis?.statement_type || 'MUTATION'})`,
    };
  }

  rollback(batchId) {
    return this._callWorker('rollback', { batchId });
  }

  verifyThreeWayMatch(input) {
    return this._callWorker('verify_three_way_match', input);
  }

  verifyTaxCompliance(input) {
    return this._callWorker('verify_tax_compliance', input);
  }

  bitemporalInsert(input) {
    return this._callWorker('bitemporal_insert', input);
  }

  bitemporalRestate(input) {
    return this._callWorker('bitemporal_restate', input);
  }

  bitemporalAsOf(input) {
    return this._callWorker('bitemporal_as_of', input);
  }

  verifyAuditChain() {
    return this._callWorker('verify_audit_chain', {});
  }

  health() {
    return this._callWorker('health', {});
  }

  async close() {
    if (this._worker && !this._worker.killed) {
      this._worker.stdin.end();
      this._worker.kill();
      this._worker = null;
    }
  }
}

export default SymbolicGateway;
