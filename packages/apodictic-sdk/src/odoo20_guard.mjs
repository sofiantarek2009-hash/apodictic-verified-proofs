/**
 * @apodictic/sdk — Odoo 18–20 JSON-2, /doc-bearer/ OpenAPI Schema & MCP Scope Firewall
 * Encodes Odoo 19/20 breaking transitions:
 *   - Deprecation of XML-RPC / legacy /jsonrpc and removal of remote `db` RPC service
 *   - POST /json/2/<model>/<method> Bearer API + X-Odoo-Database header
 *   - Mandatory bearer_scope gating ('mcp' read/staging vs 'rpc' privileged ledger ops)
 *   - hard_lock_date / fiscalyear_lock_date / inalterable_hash immutability invariants
 *   - Multi-row account.move.line integer-cent balance, multi-currency sign parity & analytic_distribution
 *   - Immutable field_diff journal compensating for Odoo 20's removal of stored chatter tracking values
 */

export const DESTRUCTIVE_ODOO_METHODS = new Set([
  'unlink',
  'button_draft',
  'button_cancel',
  'action_cancel',
  'reset_to_draft',
]);

export const PROTECTED_ACCOUNTING_MODELS = new Set([
  'account.move',
  'account.move.line',
  'account.payment',
  'account.journal',
  'res.company',
  'ir.rule',
  'ir.model.access',
]);

const VALID_X2M_CMD_CODES = new Set([0, 1, 2, 3, 4, 5, 6]);

export function toCents(val) {
  const n = Number(val ?? 0);
  if (!Number.isFinite(n)) throw new Error('Non-finite monetary value rejected');
  return Math.round(n * 100);
}

/**
 * Normalize an Odoo 20 /json/2/<model>/<method> URL or MCP tool payload into a structured call descriptor.
 */
export function extractOdoo20Call(input = {}) {
  const raw = typeof input === 'string' ? input : String(input.sql || input.payload || '');
  const odoo = input.odoo && typeof input.odoo === 'object' ? input.odoo : {};

  let urlPath = String(odoo.endpointPath || input.endpointPath || '');
  let model = String(odoo.model || input.model || '').trim();
  let method = String(odoo.method || input.method || '').trim();

  if (!model || !method) {
    const pathMatch = (urlPath || raw).match(/\/json\/2\/([a-z0-9_.]+)\/([a-z0-9_]+)/i);
    if (pathMatch) {
      model = model || pathMatch[1];
      method = method || pathMatch[2];
    }
  }

  // Detect deprecated /xmlrpc/2/ or removed /json/2/db/ RPC usage
  const lowerCombined = `${urlPath} ${raw}`.toLowerCase();
  const usesLegacyXmlRpc = /\/xmlrpc(?:\/2)?\/(?:common|object|db)/.test(lowerCombined);
  const usesRemovedDbService = /\/(?:json\/2|xmlrpc(?:\/2)?|jsonrpc)\/db\b|\bservice\s*[:=]\s*['"]?db['"]?/.test(lowerCombined)
    || model === 'db';

  const valsList = Array.isArray(odoo.valsList)
    ? odoo.valsList
    : Array.isArray(odoo.vals_list)
      ? odoo.vals_list
      : odoo.vals && typeof odoo.vals === 'object'
        ? [odoo.vals]
        : [];

  return {
    isOdooCall: Boolean(model || method || usesLegacyXmlRpc || usesRemovedDbService || odoo.bearerScope || odoo.lineItems || odoo.lines),
    model,
    method,
    urlPath,
    usesLegacyXmlRpc,
    usesRemovedDbService,
    bearerScope: odoo.bearerScope || odoo.bearer_scope || input.bearerScope || null,
    dbName: odoo.database || odoo.xOdooDatabase || input.odooDatabase || null,
    moveDate: odoo.moveDate || odoo.date || null,
    hardLockDate: odoo.hardLockDate || odoo.hard_lock_date || null,
    fiscalyearLockDate: odoo.fiscalyearLockDate || odoo.fiscalyear_lock_date || null,
    taxLockDate: odoo.taxLockDate || odoo.tax_lock_date || null,
    postedBefore: Boolean(odoo.postedBefore ?? odoo.posted_before),
    inalterableHash: odoo.inalterableHash || odoo.inalterable_hash || null,
    companyCurrencyId: odoo.companyCurrencyId || odoo.company_currency_id || 'EGP',
    cfoSigned: Boolean(input.cfoSigned ?? odoo.cfoSigned),
    openApiSchema: odoo.openApiSchema || odoo.docBearerSchema || null,
    ids: Array.isArray(odoo.ids) ? odoo.ids : [],
    valsList,
    lineItems: Array.isArray(odoo.lineItems)
      ? odoo.lineItems
      : Array.isArray(odoo.lines)
        ? odoo.lines
        : extractLinesFromVals(valsList),
    beforeRecord: odoo.beforeRecord || null,
  };
}

function extractLinesFromVals(valsList) {
  const lines = [];
  for (const vals of valsList) {
    if (!vals || typeof vals !== 'object') continue;
    const cmds = vals.line_ids || vals.invoice_line_ids;
    if (Array.isArray(cmds)) {
      for (const cmd of cmds) {
        if (Array.isArray(cmd) && (cmd[0] === 0 || cmd[0] === 1) && cmd[2] && typeof cmd[2] === 'object') {
          lines.push(cmd[2]);
        }
      }
    } else if ('debit' in vals || 'credit' in vals || 'balance' in vals || 'amount_currency' in vals || 'analytic_distribution' in vals) {
      lines.push(vals);
    }
  }
  return lines;
}

/**
 * Evaluate Odoo 18-20 structural, scope, fiscal-lock, OpenAPI schema, multi-currency,
 * and analytic_distribution invariants. Returns exact minor-unit facts for Z3/OxiZ proof.
 */
export function evaluateOdoo20Call(input = {}) {
  const call = extractOdoo20Call(input);
  if (!call.isOdooCall) {
    return {
      isOdooCall: false,
      violations: [],
      lineChecks: null,
      reversalHint: null,
      fieldDiff: null,
    };
  }

  const violations = [];
  const warnings = [];

  if (call.usesRemovedDbService) {
    violations.push('ODOO20_REMOVED_DB_RPC_BLOCKED');
  }
  if (call.usesLegacyXmlRpc) {
    warnings.push('ODOO_LEGACY_XMLRPC_DEPRECATED_USE_JSON2');
  }

  // 1. Odoo 20 mandatory bearer_scope gate for AI / MCP agents
  const scope = call.bearerScope ? String(call.bearerScope).toLowerCase() : null;
  if (scope === 'mcp') {
    const isProtectedModel = PROTECTED_ACCOUNTING_MODELS.has(call.model);
    const isDestructiveMethod = DESTRUCTIVE_ODOO_METHODS.has(call.method);
    const isPrivilegedLockWrite =
      call.model === 'res.company' &&
      call.valsList.some((v) =>
        v && Object.keys(v).some((k) => k.endsWith('_lock_date') || k === 'restrict_mode_hash_table')
      );

    if ((isProtectedModel && isDestructiveMethod) || isPrivilegedLockWrite || call.model === 'ir.rule' || call.model === 'ir.model.access') {
      if (!call.cfoSigned) {
        violations.push('INV_ODOO20_MCP_SCOPE_ESCALATION');
      }
    }
  }

  // 2. Fiscal lock dates (hard_lock_date / fiscalyear_lock_date / tax_lock_date) & inalterable_hash
  const lockCandidates = [call.hardLockDate, call.fiscalyearLockDate, call.taxLockDate].filter(Boolean).sort();
  const effectiveLockDate = lockCandidates.length > 0 ? lockCandidates[lockCandidates.length - 1] : null;
  if (call.moveDate && effectiveLockDate && String(call.moveDate) <= String(effectiveLockDate)) {
    violations.push('INV_ODOO_FISCAL_LOCK_VIOLATION');
  }

  if (
    call.inalterableHash &&
    ['write', 'unlink', 'button_draft'].includes(call.method)
  ) {
    violations.push('INV_ODOO_INALTERABLE_HASH_IMMUTABLE');
  } else if (call.postedBefore && (call.method === 'unlink' || call.valsList.some((v) => v && 'name' in v))) {
    violations.push('INV_ODOO_POSTED_BEFORE_SEQUENCE_IMMUTABLE');
  }

  // 3. OpenAPI /doc-bearer/<model>.json schema + X2many relational tuple validation
  const allowedFields = call.openApiSchema?.properties
    ? new Set(Object.keys(call.openApiSchema.properties))
    : call.openApiSchema?.fields
      ? new Set(Object.keys(call.openApiSchema.fields))
      : null;

  for (const vals of call.valsList) {
    if (!vals || typeof vals !== 'object') continue;
    for (const [k, v] of Object.entries(vals)) {
      if (allowedFields && !allowedFields.has(k)) {
        violations.push(`ODOO20_SCHEMA_UNKNOWN_FIELD:${k}`);
      }
      if ((k === 'line_ids' || k === 'invoice_line_ids' || k.endsWith('_ids')) && Array.isArray(v)) {
        for (const cmd of v) {
          if (Array.isArray(cmd)) {
            if (!VALID_X2M_CMD_CODES.has(Number(cmd[0]))) {
              violations.push(`ODOO_INVALID_X2M_COMMAND:${cmd[0]}`);
            }
          }
        }
      }
    }
  }

  // 4. Multi-row account.move.line accounting, multi-currency & analytic_distribution checks
  let debitCentsTotal = 0;
  let creditCentsTotal = 0;
  let mutuallyExclusiveViolation = false;
  let currencyParityViolation = false;
  let analyticDistributionViolation = false;
  let analyticPercentSum = null;

  if (call.lineItems.length > 0) {
    for (const line of call.lineItems) {
      const dCents = toCents(line.debit ?? 0);
      const cCents = toCents(line.credit ?? 0);
      if (dCents < 0 || cCents < 0 || (dCents > 0 && cCents > 0)) {
        mutuallyExclusiveViolation = true;
      }
      debitCentsTotal += dCents;
      creditCentsTotal += cCents;

      const balanceCents = line.balance !== undefined ? toCents(line.balance) : dCents - cCents;
      if (line.amount_currency !== undefined) {
        const acCents = toCents(line.amount_currency);
        const lineCurr = line.currency_id || call.companyCurrencyId;
        if (lineCurr === call.companyCurrencyId && acCents !== balanceCents) {
          currencyParityViolation = true;
        } else if ((acCents > 0 && balanceCents < 0) || (acCents < 0 && balanceCents > 0)) {
          currencyParityViolation = true;
        }
      }

      if (line.analytic_distribution && typeof line.analytic_distribution === 'object') {
        const weights = Object.values(line.analytic_distribution).map(Number);
        if (weights.some((w) => !Number.isFinite(w) || w < 0 || w > 100)) {
          analyticDistributionViolation = true;
        } else if (weights.length > 0) {
          analyticPercentSum = Number(weights.reduce((a, b) => a + b, 0).toFixed(4));
          if (Math.abs(analyticPercentSum - 100.0) > 0.01) {
            analyticDistributionViolation = true;
          }
        }
      }
    }

    if (mutuallyExclusiveViolation) {
      violations.push('INV_ODOO_LINE_DEBIT_CREDIT_MUTEX');
    }
    if (currencyParityViolation) {
      violations.push('INV_ODOO_MULTICURRENCY_SIGN_PARITY');
    }
    if (analyticDistributionViolation) {
      violations.push('INV_ODOO_ANALYTIC_DISTRIBUTION_100PCT');
    }
  }

  // Build non-destructive compensating credit-note reversal payload for Odoo 18-20
  const targetMoveId = call.ids[0] ?? null;
  const reversalHint = {
    protocol: 'ODOO_JSON2_POST',
    endpoint: '/json/2/account.move.reversal/create',
    followUpEndpoint: '/json/2/account.move.reversal/reverse_moves',
    headers: {
      Authorization: 'Bearer <ODOO_API_KEY>',
      'X-Odoo-Database': call.dbName || '<ODOO_DB>',
      'Content-Type': 'application/json',
    },
    body: {
      vals_list: [
        {
          reason: 'Apodictic Z3/OxiZ compensating reversal (inalterable audit preservation)',
          ...(call.moveDate ? { date: call.moveDate } : {}),
        },
      ],
      context: {
        active_model: call.model || 'account.move',
        active_ids: targetMoveId ? [targetMoveId] : [],
      },
    },
  };

  // Capture immutable field diff to replace removed Odoo 20 stored chatter tracking values
  const fieldDiff = {
    model: call.model,
    method: call.method,
    ids: call.ids,
    before: call.beforeRecord,
    proposed: call.valsList[0] ?? null,
    preservedReason: 'Odoo 20 removed stored chatter tracking values; sealed in Apodictic WORM vault',
  };

  return {
    isOdooCall: true,
    model: call.model,
    method: call.method,
    bearerScope: scope,
    violations,
    warnings,
    lineChecks: call.lineItems.length > 0
      ? {
          lineCount: call.lineItems.length,
          debitCentsTotal,
          creditCentsTotal,
          debitTotal: Number((debitCentsTotal / 100).toFixed(2)),
          creditTotal: Number((creditCentsTotal / 100).toFixed(2)),
          mutuallyExclusiveViolation,
          currencyParityViolation,
          analyticDistributionViolation,
          analyticPercentSum,
        }
      : null,
    reversalHint,
    fieldDiff,
  };
}

export default {
  extractOdoo20Call,
  evaluateOdoo20Call,
  DESTRUCTIVE_ODOO_METHODS,
  PROTECTED_ACCOUNTING_MODELS,
};
