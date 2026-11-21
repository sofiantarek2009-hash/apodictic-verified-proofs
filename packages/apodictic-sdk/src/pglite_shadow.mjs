/**
 * @apodictic/sdk — PGlite WASM Shadow Postgres Firewall ("Execute-Then-Prove")
 * Executes candidate SQL inside a rolled-back in-memory Postgres 17 WASM transaction,
 * observes actual post-execution state diffs (triggers, subqueries, CASE WHEN, CTEs,
 * cascading deletes), unconditionally rolls back, and proves solvency/cap invariants via Z3 5.4.1.
 */
import { PGlite } from '@electric-sql/pglite';

const DEFAULT_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  balance DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS vendor_disbursements (
  id INT PRIMARY KEY,
  account_id TEXT NOT NULL,
  amount DOUBLE PRECISION NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'PENDING',
  vendor_iban TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS ledger_entries (
  id SERIAL PRIMARY KEY,
  account_id TEXT NOT NULL,
  delta DOUBLE PRECISION NOT NULL,
  memo TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`;

export class ShadowPostgresVerifier {
  constructor(gatewayOrOptions = null, maybeOptions = {}) {
    if (gatewayOrOptions && typeof gatewayOrOptions.verifyMutation === 'function') {
      this._gateway = gatewayOrOptions;
      this._ownGateway = null;
      this.options = maybeOptions || {};
    } else {
      this.options = (gatewayOrOptions && typeof gatewayOrOptions === 'object') ? gatewayOrOptions : {};
      this._gateway = this.options.gateway && typeof this.options.gateway.verifyMutation === 'function'
        ? this.options.gateway
        : null;
      this._ownGateway = null;
    }
    this._db = null;
  }

  async _getGateway() {
    if (this._gateway) return this._gateway;
    if (!this._ownGateway) {
      const { SymbolicGateway } = await import('./index.mjs');
      this._ownGateway = new SymbolicGateway(this.options);
    }
    return this._ownGateway;
  }

  async _ensureDefaultDb(accountId, currentBalance) {
    if (!this._db) {
      this._db = new PGlite();
      await this._db.exec(DEFAULT_SCHEMA_SQL);
    }
    await this._db.query(
      'INSERT INTO accounts (id, balance) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET balance = EXCLUDED.balance',
      [accountId, currentBalance]
    );
    await this._db.query(
      `INSERT INTO vendor_disbursements (id, account_id, amount, status, vendor_iban)
       VALUES (1, $1, 0, 'PENDING', ''), (4092, $1, 0, 'PENDING', '')
       ON CONFLICT (id) DO NOTHING`,
      [accountId]
    );
    return this._db;
  }

  async shadowExecuteAndProve(input = {}) {
    const t0 = performance.now();
    const sql = String(input.sql || '');
    const accountId = String(input.accountId || 'sdk_default');
    const hasExplicitBal = input.currentBalance !== undefined && input.currentBalance !== null;
    const explicitAmount =
      input.amount !== undefined && input.amount !== null ? Number(input.amount) : undefined;
    const minReserve = Number(input.minReserve ?? 50000);
    const maxAutonomousLimit = Number(input.maxAutonomousLimit ?? 50000);
    const cfoSigned = Boolean(input.cfoSigned);
    const schemaSql = typeof input.schemaSql === 'string' ? input.schemaSql.trim() : '';
    const seedSql = typeof input.seedSql === 'string' ? input.seedSql.trim() : '';
    const useFreshTemp = Boolean(schemaSql || seedSql);

    let tempDb = null;
    let db;
    if (useFreshTemp) {
      tempDb = new PGlite();
      db = tempDb;
      await db.exec(schemaSql || DEFAULT_SCHEMA_SQL);
      if (seedSql) {
        await db.exec(seedSql);
      } else {
        await db.query(
          'INSERT INTO accounts (id, balance) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET balance = EXCLUDED.balance',
          [accountId, hasExplicitBal ? Number(input.currentBalance) : 250000]
        );
      }
    } else {
      db = await this._ensureDefaultDb(accountId, hasExplicitBal ? Number(input.currentBalance) : 250000);
    }

    let hasAccountsTable = false;
    let preBalances = {};
    let totalBefore = 0;
    let postBalances = {};
    let totalAfter = 0;
    let rowsAffected = 0;
    let executionError = null;
    let ddlOrTableDropped = false;
    let inTx = false;
    let observedDebitTotal = input.debitTotal !== undefined ? Number(input.debitTotal) : undefined;
    let observedCreditTotal = input.creditTotal !== undefined ? Number(input.creditTotal) : undefined;

    // Strip comments and string literals before rejecting transaction-control escape statements
    const txControlProbe = sql
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/--[^\n]*/g, ' ')
      .replace(/'(?:''|[^'])*'/g, " '' ");
    const hasTxControlEscape = /\b(?:COMMIT|END\s+(?:TRANSACTION|WORK)|ROLLBACK\s+TO|ROLLBACK\b|BEGIN\b|START\s+TRANSACTION|SAVEPOINT|RELEASE\s+SAVEPOINT)\b/i.test(
      txControlProbe
    );

    try {
      const regPre = await db.query("SELECT to_regclass('public.accounts') AS tbl");
      hasAccountsTable = Boolean(regPre.rows?.[0]?.tbl);
      if (hasAccountsTable) {
        const preRes = await db.query('SELECT id, balance FROM accounts ORDER BY id ASC');
        for (const r of preRes.rows) {
          const bal = Number(r.balance);
          preBalances[String(r.id)] = bal;
          totalBefore += bal;
        }
      }
      postBalances = { ...preBalances };
      totalAfter = totalBefore;

      if (hasTxControlEscape) {
        ddlOrTableDropped = true;
        executionError = 'TRANSACTION_CONTROL_ESCAPE_BLOCKED: COMMIT/BEGIN/ROLLBACK forbidden inside shadow probe';
      } else {
        await db.exec('BEGIN;');
        inTx = true;
        const execResults = await db.exec(sql);
        for (const r of execResults) {
          rowsAffected += Number(r.affectedRows ?? r.rowCount ?? 0);
          const cmd = String(r.command || '').toUpperCase();
          if (cmd === 'DROP' || cmd === 'TRUNCATE' || cmd === 'ALTER' || cmd === 'CREATE' || cmd === 'COPY') {
            ddlOrTableDropped = true;
          }
        }

        if (hasAccountsTable) {
          const regPost = await db.query("SELECT to_regclass('public.accounts') AS tbl");
          if (!regPost.rows?.[0]?.tbl) {
            ddlOrTableDropped = true;
            postBalances = {};
            totalAfter = 0;
          } else {
            const postRes = await db.query('SELECT id, balance FROM accounts ORDER BY id ASC');
            postBalances = {};
            totalAfter = 0;
            for (const r of postRes.rows) {
              const bal = Number(r.balance);
              postBalances[String(r.id)] = bal;
              totalAfter += bal;
            }
          }
        }

        const regMove = await db.query("SELECT to_regclass('public.account_move_line') AS tbl");
        if (regMove.rows?.[0]?.tbl && observedDebitTotal === undefined && observedCreditTotal === undefined) {
          const deRes = await db.query('SELECT COALESCE(SUM(debit), 0) AS d, COALESCE(SUM(credit), 0) AS c FROM account_move_line');
          if (deRes.rows?.[0]) {
            observedDebitTotal = Number(deRes.rows[0].d);
            observedCreditTotal = Number(deRes.rows[0].c);
          }
        }
      }
    } catch (err) {
      executionError = err instanceof Error ? err.message : String(err);
    } finally {
      if (inTx) {
        try {
          await db.exec('ROLLBACK;');
        } catch {
          // ignore rollback error on aborted cleanup
        }
      }
      if (tempDb) {
        try {
          await tempDb.close();
        } catch {
          // ignore temp close error
        }
      }
    }

    const observedDeltas = {};
    let grossOutflow = 0;
    for (const id of new Set([...Object.keys(preBalances), ...Object.keys(postBalances)])) {
      const before = preBalances[id] ?? 0;
      const after = postBalances[id] ?? 0;
      if (before !== after || !(id in postBalances) || !(id in preBalances)) {
        const delta = Number((after - before).toFixed(4));
        if (before > after) grossOutflow += before - after;
        observedDeltas[id] = {
          before,
          after,
          delta,
        };
      }
    }

    const observedDebit = executionError
      ? 0
      : Number(Math.max(grossOutflow, Math.max(0, totalBefore - totalAfter)).toFixed(4));

    const currentBalance = hasExplicitBal
      ? Number(input.currentBalance)
      : (preBalances[accountId] ?? (Object.keys(preBalances).length > 0 ? totalBefore : 250000));

    const effectiveAmount =
      explicitAmount !== undefined || observedDebit > 0
        ? Math.max(explicitAmount || 0, observedDebit)
        : undefined;

    const gw = await this._getGateway();
    const z3Proof = await gw.verifyMutation({
      sql,
      action: input.action,
      accountId,
      amount: effectiveAmount,
      currentBalance,
      minReserve,
      maxAutonomousLimit,
      cfoSigned,
      debitTotal: observedDebitTotal,
      creditTotal: observedCreditTotal,
      statutoryVat: input.statutoryVat,
      expectedVat: input.expectedVat,
      targetSystem: input.targetSystem,
      odoo: input.odoo,
    });

    const failClosed = Boolean(executionError) || ddlOrTableDropped;
    const verified = !failClosed && Boolean(z3Proof.verified);
    const verdict = verified ? 'SAT' : 'UNSAT';
    const reason = executionError
      ? `EXECUTION_ERROR: ${executionError}`
      : ddlOrTableDropped
        ? (z3Proof.reason || 'DDL_OR_DESTRUCTIVE_MUTATION_BLOCKED')
        : (z3Proof.reason ?? null);

    return {
      verdict,
      verified,
      engine: 'apodictic-pglite-shadow-z3',
      rowsAffected,
      observedDebit,
      observedDeltas,
      postBalances,
      z3Proof,
      counterfactualPatch: verified ? null : (z3Proof.counterfactualPatch ?? null),
      reason,
      executionError,
      latencyMs: Number((performance.now() - t0).toFixed(3)),
    };
  }

  async close() {
    if (this._db) {
      await this._db.close();
      this._db = null;
    }
    if (this._ownGateway) {
      await this._ownGateway.close();
      this._ownGateway = null;
    }
  }
}

export { PGlite };
export default ShadowPostgresVerifier;
