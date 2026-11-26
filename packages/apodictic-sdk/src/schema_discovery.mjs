/**
 * @apodictic/sdk — Read-Only PostgreSQL & Odoo Schema Auto-Discovery + Policy IR Generator
 *
 * Scans DDL strings, live PostgreSQL DSNs (`information_schema`, `pg_trigger`, `ON DELETE CASCADE`),
 * or Odoo 18–20 `/doc-bearer/<model>.json` OpenAPI schemas to detect financial/inventory tables and
 * auto-generate a Z3-deadlock-verified Policy IR bundle starting safely in `OBSERVE` mode.
 */
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { checkPolicyIrDeadlockWasm } from './z3_wasm_verifier.mjs';

const require = createRequire(import.meta.url);

const TREASURY_TABLE_HINTS = [
  'account',
  'accounts',
  'ledger',
  'journal',
  'account_move',
  'account_move_line',
  'account_payment',
  'payout',
  'disbursement',
  'transfer',
  'wire',
  'invoice',
  'tax_chain',
  'fiscal',
  'treasury',
];

const INVENTORY_TABLE_HINTS = [
  'stock_quant',
  'stock_move',
  'stock_picking',
  'inventory',
  'warehouse',
  'product_pricelist',
];

const BALANCE_COL_HINTS = ['balance', 'amount', 'debit', 'credit', 'reserve', 'total', 'qty', 'quantity'];

function classifyTable(tableName, cols = []) {
  const low = String(tableName || '').toLowerCase();
  const isOdooCore =
    low.startsWith('account_') ||
    low.startsWith('account.') ||
    low.startsWith('stock_') ||
    low.startsWith('stock.') ||
    low.includes('pricelist');
  const isFinancial =
    TREASURY_TABLE_HINTS.some((h) => low.includes(h)) ||
    cols.some((c) => BALANCE_COL_HINTS.some((h) => String(c).toLowerCase().includes(h)));
  const isInventory = INVENTORY_TABLE_HINTS.some((h) => low.includes(h));
  const isProtectedTax = low.includes('tax') || low.includes('fiscal') || low.includes('account_move');
  return { isFinancial, isInventory, isProtectedTax, isOdooCore };
}

export function discoverSchemaFromSql(ddlSql, options = {}) {
  const sql = String(ddlSql || '');
  const tables = [];

  // Parse CREATE TABLE statements cleanly across PG/SQLite dialects
  const tableRe =
    /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:["`]?([A-Za-z_][A-Za-z0-9_$.]*)["`]?)\s*\(([\s\S]*?)\)\s*;/gi;
  let m;
  while ((m = tableRe.exec(sql)) !== null) {
    const rawName = m[1].split('.').pop();
    const body = m[2];
    const columns = [];
    const cascades = [];

    for (const rawLine of body.split(/,(?![^(]*\))/)) {
      const line = rawLine.trim();
      if (!line) continue;
      if (/ON\s+DELETE\s+CASCADE/i.test(line)) {
        const refM = line.match(/REFERENCES\s+["`]?([A-Za-z_][A-Za-z0-9_$.]*)["`]?/i);
        cascades.push({
          table: rawName,
          references: refM ? refM[1] : 'parent_table',
          definition: line.slice(0, 140),
        });
      }
      if (/^(CONSTRAINT|PRIMARY\s+KEY|FOREIGN\s+KEY|UNIQUE|CHECK)\b/i.test(line)) {
        continue;
      }
      const colMatch = line.match(/^["`]?([A-Za-z_][A-Za-z0-9_$]*)["`]?\s+([A-Za-z0-9_()\s]+)/i);
      if (colMatch) {
        columns.push({
          name: colMatch[1],
          type: colMatch[2].trim().split(/\s+(?:NOT|NULL|PRIMARY|DEFAULT|REFERENCES|CHECK)\b/i)[0].trim(),
        });
      }
    }

    const colNames = columns.map((c) => c.name);
    const kind = classifyTable(rawName, colNames);
    tables.push({
      name: rawName,
      columns,
      cascades,
      ...kind,
    });
  }

  // Detect hidden triggers (`CREATE TRIGGER ... ON <table> ... EXECUTE ...`)
  const triggers = [];
  const trigRe =
    /CREATE\s+(?:OR\s+REPLACE\s+)?(?:CONSTRAINT\s+)?TRIGGER\s+["`]?([A-Za-z_][A-Za-z0-9_$]*)["`]?\s+(BEFORE|AFTER|INSTEAD\s+OF)\s+(INSERT|UPDATE|DELETE(?:\s+OR\s+(?:INSERT|UPDATE|DELETE))*)\s+(?:OF\s+[^\s]+\s+)?ON\s+["`]?([A-Za-z_][A-Za-z0-9_$.]*)["`]?/gi;
  while ((m = trigRe.exec(sql)) !== null) {
    triggers.push({
      name: m[1],
      timing: m[2].toUpperCase(),
      events: m[3].toUpperCase(),
      table: m[4].split('.').pop(),
    });
  }

  const allCascades = tables.flatMap((t) =>
    t.cascades.map((c) => ({ table: t.name, references: c.references, rule: 'CASCADE' }))
  );

  return {
    source: options.source || 'sql_ddl',
    tables,
    triggers,
    cascades: allCascades,
    savepointRecommended: triggers.length > 0 || allCascades.length > 0,
  };
}

export async function discoverSchemaFromPgDsn(dsn, options = {}) {
  const connStr = String(dsn || '').trim();
  if (!connStr) {
    throw new Error('discoverSchemaFromPgDsn requires a PostgreSQL connection string');
  }

  let Pool = options.Pool;
  if (!Pool) {
    let pgMod;
    try {
      pgMod = await import('pg');
    } catch {
      const here = path.dirname(new URL(import.meta.url).pathname);
      const resolved = require.resolve('pg', {
        paths: [
          process.cwd(),
          path.resolve(process.cwd(), 'frontend'),
          path.resolve(here, '..'),
          path.resolve(here, '../../../frontend'),
        ],
      });
      pgMod = await import(pathToFileURL(resolved).href);
    }
    Pool = pgMod.Pool || pgMod.default?.Pool;
  }

  const pool = new Pool({ connectionString: connStr, max: 2 });
  const schemaName = options.schema || 'public';
  try {
    const colRes = await pool.query(
      `SELECT table_name, column_name, data_type
       FROM information_schema.columns
       WHERE table_schema = $1
       ORDER BY table_name, ordinal_position`,
      [schemaName]
    );

    const trigRes = await pool.query(
      `SELECT tg.tgname AS trigger_name, cls.relname AS table_name, pg_get_triggerdef(tg.oid) AS def
       FROM pg_trigger tg
       JOIN pg_class cls ON cls.oid = tg.tgrelid
       JOIN pg_namespace ns ON ns.oid = cls.relnamespace
       WHERE ns.nspname = $1 AND NOT tg.tgisinternal`,
      [schemaName]
    );

    const fkRes = await pool.query(
      `SELECT tc.table_name, kcu.column_name, rc.delete_rule, ccu.table_name AS ref_table
       FROM information_schema.table_constraints tc
       JOIN information_schema.referential_constraints rc
         ON tc.constraint_schema = rc.constraint_schema AND tc.constraint_name = rc.constraint_name
       JOIN information_schema.key_column_usage kcu
         ON tc.constraint_schema = kcu.constraint_schema AND tc.constraint_name = kcu.constraint_name
       JOIN information_schema.constraint_column_usage ccu
         ON rc.unique_constraint_schema = ccu.constraint_schema AND rc.unique_constraint_name = ccu.constraint_name
       WHERE tc.table_schema = $1 AND rc.delete_rule = 'CASCADE'`,
      [schemaName]
    );

    const tableMap = new Map();
    for (const row of colRes.rows) {
      if (!tableMap.has(row.table_name)) {
        tableMap.set(row.table_name, []);
      }
      tableMap.get(row.table_name).push({ name: row.column_name, type: row.data_type });
    }

    const tables = [...tableMap.entries()].map(([name, columns]) => ({
      name,
      columns,
      cascades: fkRes.rows
        .filter((f) => f.table_name === name)
        .map((f) => ({ table: name, references: f.ref_table, rule: 'CASCADE' })),
      ...classifyTable(name, columns.map((c) => c.name)),
    }));

    const triggers = trigRes.rows.map((r) => ({
      name: r.trigger_name,
      timing: /\bBEFORE\b/i.test(r.def) ? 'BEFORE' : 'AFTER',
      events: /\bDELETE\b/i.test(r.def) ? 'DELETE' : /\bUPDATE\b/i.test(r.def) ? 'UPDATE' : 'INSERT',
      table: r.table_name,
    }));

    const cascades = fkRes.rows.map((f) => ({
      table: f.table_name,
      column: f.column_name,
      references: f.ref_table,
      rule: f.delete_rule,
    }));

    return {
      source: 'postgresql_live_dsn',
      schema: schemaName,
      tables,
      triggers,
      cascades,
      savepointRecommended: triggers.length > 0 || cascades.length > 0,
    };
  } finally {
    await pool.end();
  }
}

export async function discoverSchemaFromOdoo(odooUrl, options = {}) {
  const base = String(odooUrl || '').trim().replace(/\/+$/, '');
  if (!base) {
    throw new Error('discoverSchemaFromOdoo requires an Odoo base URL');
  }
  const models = options.models || [
    'account.move',
    'account.payment',
    'stock.quant',
    'product.pricelist.item',
  ];
  const headers = {};
  if (options.token) {
    headers.Authorization = `Bearer ${options.token}`;
  }
  if (options.db) {
    headers['X-Odoo-Database'] = options.db;
  }

  const tables = [];
  for (const model of models) {
    const url = `${base}/doc-bearer/${encodeURIComponent(model)}.json`;
    try {
      const resp = await fetch(url, { headers, signal: AbortSignal.timeout(4000) });
      if (!resp.ok) continue;
      const spec = await resp.json();
      const props =
        spec?.components?.schemas?.[model]?.properties ||
        spec?.properties ||
        {};
      const columns = Object.entries(props).map(([name, meta]) => ({
        name,
        type: String(meta?.type || 'string'),
      }));
      tables.push({
        name: model.replace(/\./g, '_'),
        odooModel: model,
        columns,
        cascades: [],
        ...classifyTable(model, columns.map((c) => c.name)),
      });
    } catch {
      // ignore unreachable optional model endpoint
    }
  }

  if (tables.length === 0) {
    // Fallback default Odoo financial topology if /doc-bearer/ isn't exposed without bearer scopes
    for (const model of models) {
      tables.push({
        name: model.replace(/\./g, '_'),
        odooModel: model,
        columns: [{ name: 'amount_total', type: 'number' }],
        cascades: [],
        inferredFallback: true,
        ...classifyTable(model, ['amount_total']),
      });
    }
  }

  return {
    source: 'odoo_doc_bearer',
    odooUrl: base,
    tables,
    triggers: [],
    cascades: [],
    savepointRecommended: false,
  };
}

export async function compileDiscoveredPolicyIr(discovery, options = {}) {
  const capUsd = Number.isFinite(Number(options.spendCapUsd)) ? Number(options.spendCapUsd) : 50000;
  const reserveUsd = Number.isFinite(Number(options.minReserveUsd)) ? Number(options.minReserveUsd) : 25000;
  const maxDiscountPct = Number.isFinite(Number(options.maxDiscountPct)) ? Number(options.maxDiscountPct) : 15;
  const maxBranches = Number.isFinite(Number(options.maxBranches)) ? Number(options.maxBranches) : 1;

  const tables = discovery?.tables || [];
  const triggers = discovery?.triggers || [];
  const cascades = discovery?.cascades || [];

  const financialTables = tables.filter((t) => t.isFinancial).map((t) => t.name);
  const inventoryTables = tables.filter((t) => t.isInventory).map((t) => t.name);
  const protectedTables = [...new Set(tables.filter((t) => t.isProtectedTax || t.isFinancial).map((t) => t.name))];
  if (protectedTables.length === 0) {
    protectedTables.push('account_move', 'tax_chain');
  }

  const clauses = [
    { kind: 'min_reserve_floor', reserveUsd },
    { kind: 'max_payout_cap', limitUsd: capUsd, requireCfoAbove: true },
  ];

  if (inventoryTables.length > 0 || tables.some((t) => t.name.includes('pricelist'))) {
    clauses.push({
      kind: 'stock_conservation',
      requireNonNegative: true,
      requireZeroNetInternalTransfer: true,
    });
    clauses.push({ kind: 'max_discount_pct', maxPct: maxDiscountPct });
    clauses.push({ kind: 'max_branch_blast_radius', maxBranches });
  }

  clauses.push({
    kind: 'forbid_destructive',
    protectedTables: protectedTables.slice(0, 8),
  });

  const warnings = [];
  for (const tr of triggers) {
    warnings.push({
      severity: 'HIGH',
      kind: 'HIDDEN_PLPGSQL_TRIGGER',
      target: `${tr.table}.${tr.name}`,
      detail: `${tr.timing} ${tr.events} trigger on '${tr.table}' can mutate state outside client SQL AST; --savepoint-mode required.`,
    });
  }
  for (const fk of cascades) {
    warnings.push({
      severity: 'HIGH',
      kind: 'ON_DELETE_CASCADE_FK',
      target: `${fk.table} -> ${fk.references}`,
      detail: `Cascading delete on '${fk.table}' can purge audit/tax rows via parent delete; --savepoint-mode required.`,
    });
  }

  const deadlockCheck = await checkPolicyIrDeadlockWasm(clauses);
  const policyIr = {
    version: '1.0',
    name: options.name || 'apodictic-autodiscovered-policy',
    recommendedMode: 'OBSERVE',
    savepointModeRecommended: Boolean(discovery?.savepointRecommended),
    discoveredFrom: discovery?.source || 'unknown',
    detectedTables: tables.map((t) => ({
      name: t.name,
      columns: (t.columns || []).map((c) => c.name || c),
      isFinancial: Boolean(t.isFinancial),
      isInventory: Boolean(t.isInventory),
      isProtectedTax: Boolean(t.isProtectedTax),
    })),
    clauses,
    warnings,
    deadlock_check: deadlockCheck,
    launch_commands: {
      postgres_observe: `apodictic_pg_proxy --listen 127.0.0.1:5433 --upstream 127.0.0.1:5432 --mode observe${discovery?.savepointRecommended ? ' --savepoint-mode' : ''} --min-reserve ${reserveUsd} --spend-cap ${capUsd}`,
      postgres_enforce: `apodictic_pg_proxy --listen 127.0.0.1:5433 --upstream 127.0.0.1:5432 --mode enforce${discovery?.savepointRecommended ? ' --savepoint-mode' : ''} --min-reserve ${reserveUsd} --spend-cap ${capUsd}`,
      odoo_observe: `npx apodictic-mcp-verifier wrap-odoo --upstream http://127.0.0.1:8069 --listen 127.0.0.1:8070 --mode observe --report-out ./apodictic-shadow.jsonl`,
    },
  };

  return {
    policy_ir: policyIr,
    deadlock_check: deadlockCheck,
    financial_tables: financialTables,
    inventory_tables: inventoryTables,
    warnings,
    savepoint_recommended: Boolean(discovery?.savepointRecommended),
  };
}
