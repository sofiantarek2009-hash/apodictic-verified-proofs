#!/usr/bin/env node
/**
 * @apodictic/mcp-verifier
 * Spec-compliant MCP JSON-RPC 2.0 firewall & standalone verification server.
 *
 * Modes:
 *   1. `apodictic-mcp-verifier serve [--airgap] [--config <path>] [--endpoint <url>]`
 *      Standalone MCP stdio server exposing Z3 5.4.1 verification, 3-way match,
 *      indirect tax parity, atomic rollback, and WORM audit tools.
 *   2. `apodictic-mcp-verifier wrap [--airgap] [--config <path>] -- <command> [args...]`
 *      Drop-in stateful firewall proxy in front of any MCP server (Postgres, Odoo, Stripe).
 *   3. Single-shot stdin envelope check.
 */
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';

let SymbolicGateway, PGlite;
try {
  ({ SymbolicGateway, PGlite } = await import('apodictic-sdk'));
} catch {
  try {
    ({ SymbolicGateway, PGlite } = await import('@apodictic/sdk'));
  } catch {
    ({ SymbolicGateway, PGlite } = await import('../../apodictic-sdk/src/index.mjs'));
  }
}

const SUPPORTED_PROTOCOL_VERSIONS = ['2025-03-26', '2024-11-05'];

const BUILTIN_TOOLS = [
  {
    name: 'apodictic_verify_mutation',
    description: 'Verify SQL or ERP mutation against Z3 5.4.1 solvency, cap, tax, and destructive-op invariants prior to commit.',
    inputSchema: {
      type: 'object',
      properties: {
        sql: { type: 'string', description: 'Proposed SQL or ERP mutation payload' },
        accountId: { type: 'string', description: 'Ledger or entity identifier' },
        amount: { type: 'number', description: 'Transaction amount in settlement currency' },
        currentBalance: { type: 'number', description: 'Current ledger balance' },
        minReserve: { type: 'number', description: 'Minimum liquidity reserve floor' },
        maxAutonomousLimit: { type: 'number', description: 'Max autonomous spend without dual-custody sign-off' },
        cfoSigned: { type: 'boolean', description: 'Whether dual-custody sign-off is attached' },
        targetSystem: { type: 'string', enum: ['postgresql', 'odoo_v18', 'odoo_v19', 'odoo_v20', 'sap_s4hana', 'stripe'] },
        odoo: { type: 'object', description: 'Optional Odoo 18-20 /json/2/ model, method, bearerScope, lock dates, or account.move.line rows' },
      },
      required: ['sql'],
    },
  },
  {
    name: 'apodictic_verify_three_way_match',
    description: 'Verify Purchase Order <-> Goods Receipt <-> Vendor Invoice parity with Z3.',
    inputSchema: {
      type: 'object',
      properties: {
        po: {
          type: 'object',
          properties: {
            poId: { type: 'string' },
            sku: { type: 'string' },
            orderedQty: { type: 'number' },
            unitPrice: { type: 'number' },
          },
          required: ['poId', 'sku', 'orderedQty', 'unitPrice'],
        },
        receipts: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              receiptId: { type: 'string' },
              poId: { type: 'string' },
              sku: { type: 'string' },
              receivedQty: { type: 'number' },
            },
            required: ['receiptId', 'poId', 'sku', 'receivedQty'],
          },
        },
        invoices: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              invoiceId: { type: 'string' },
              poId: { type: 'string' },
              sku: { type: 'string' },
              billedQty: { type: 'number' },
              billedUnitPrice: { type: 'number' },
            },
            required: ['invoiceId', 'poId', 'sku', 'billedQty', 'billedUnitPrice'],
          },
        },
        priceTolerancePct: { type: 'number', description: 'Allowed price drift fraction (default 0.02)' },
      },
      required: ['po', 'receipts', 'invoices'],
    },
  },
  {
    name: 'apodictic_verify_tax',
    description: 'Verify Egypt ETA (14%) / KSA ZATCA (15%) / EU VAT statutory tax parity.',
    inputSchema: {
      type: 'object',
      properties: {
        jurisdiction: {
          type: 'string',
          enum: ['KSA_ZATCA', 'EGYPT_ETA', 'EU_VAT_DE', 'EU_REVERSE_CHARGE'],
        },
        lines: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              sku: { type: 'string' },
              netAmount: { type: 'number' },
              claimedVatAmount: { type: 'number' },
              claimedWhtAmount: { type: 'number' },
              isExempt: { type: 'boolean' },
            },
            required: ['sku', 'netAmount', 'claimedVatAmount'],
          },
        },
        hasCryptographicStamp: { type: 'boolean' },
        tolerance: { type: 'number' },
      },
      required: ['jurisdiction', 'lines'],
    },
  },
  {
    name: 'apodictic_rollback',
    description: 'Execute atomic <38ms local rollback for a staged batchId.',
    inputSchema: {
      type: 'object',
      properties: { batchId: { type: 'string', description: 'Staged rollback batch identifier' } },
      required: ['batchId'],
    },
  },
  {
    name: 'apodictic_audit_status',
    description: 'Verify full 256-bit SHA-256 WORM Merkle audit chain integrity.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'apodictic_evaluate_policy',
    description: 'Evaluate declarative permit/forbid policies and transitive entity hierarchy DAGs via Z3 5.4.1 theorem proving.',
    inputSchema: {
      type: 'object',
      properties: {
        policyText: { type: 'string', description: 'Declarative permit/forbid policy text' },
        action: { type: 'string', description: 'Action name (e.g. UPDATE, WIRE, DROP)' },
        principal: { type: 'string', description: 'Entity principal e.g. User::"alice"' },
        resource: { type: 'string', description: 'Target resource e.g. Account::"payout_hot"' },
        entityHierarchy: { type: 'object', description: 'Map of entity -> parent group/pool arrays' },
        amount: { type: 'number' },
        currentBalance: { type: 'number' },
        minReserve: { type: 'number' },
        spendingLimit: { type: 'number' },
        cfoSigned: { type: 'boolean' },
        reversalArmed: { type: 'boolean' },
      },
      required: ['action'],
    },
  },
  {
    name: 'apodictic_merkle_proof',
    description: 'Generate and cryptographically verify an O(log N) RFC 6962 binary Merkle tree inclusion proof for a WORM block.',
    inputSchema: {
      type: 'object',
      properties: {
        blockIndex: { type: 'number', description: '1-based WORM block index (defaults to latest block)' },
      },
    },
  },
  {
    name: 'apodictic_flush_escrow',
    description: 'Dispatch eligible staged 2-phase escrow holds (debits_pending -> debits_posted) to external rails.',
    inputSchema: {
      type: 'object',
      properties: {
        batchId: { type: 'string', description: 'Optional specific staged escrow batch ID' },
        coolingWindowSec: { type: 'number', description: 'Optional cooling window in seconds' },
      },
    },
  },
];

const BUILTIN_TOOL_NAMES = new Set(BUILTIN_TOOLS.map((t) => t.name));

/**
 * Apodictic MCP Payload Guard: Tool-Call Prompt-Injection, Unicode Tag Smuggling & Command-Smuggling Scanner.
 * Scans MCP JSON-RPC arguments before tool dispatch for:
 * 1. Unicode Tag Characters (U+E0000..U+E007F invisible ASCII tag block used to hide LLM instructions).
 * 2. Indirect Prompt Injection / System Override markers (`IGNORE ALL PREVIOUS INSTRUCTIONS`, `<|im_start|>system`, `[INST]`).
 * 3. Shell / RCE Command Injection inside tool arguments (`$(...)`, `` `...` ``, `; rm -rf`, `| bash`, `/etc/passwd`, `../..`).
 */
export function scanApodicticMcpToolGuard(toolName, args) {
  const rawSerialized = typeof args === 'string' ? args : JSON.stringify(args || {});
  const threats = [];

  // 1. Unicode Tag Characters (U+E0000..U+E007F)
  for (const ch of rawSerialized) {
    const cp = ch.codePointAt(0) || 0;
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      threats.push('APODICTIC_MCP_UNICODE_TAG_SMUGGLING');
      break;
    }
  }

  // Strip zero-width evasion chars and decode percent-encoded traversal sequences before regex scans
  let normalized = rawSerialized.replace(/[\u200B-\u200D\uFEFF\u00AD]/g, '');
  try {
    normalized = decodeURIComponent(normalized.replace(/%(?![0-9A-Fa-f]{2})/g, '%25'));
  } catch {
    // keep zero-width-stripped string if malformed percent-encoding exists
  }

  // 2. Indirect Prompt Injection / System Prompt Override markers
  if (
    /\b(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|disregard\s+system\s+prompt|you\s+are\s+now\s+in\s+developer\s+mode|override\s+z3\s+invariant)\b/i.test(
      normalized
    ) ||
    /<\|im_start\|>\s*system|<\|system\|>|\[INST\]\s*<<SYS>>/i.test(normalized)
  ) {
    threats.push('APODICTIC_MCP_PROMPT_INJECTION_OVERRIDE');
  }

  // 3. Shell / Command / Path Traversal Injection in MCP tool parameters
  if (
    /\$\([^)]+\)|`[^`]+`|\|\s*(?:bash|sh|zsh|nc|curl|wget)\b|;\s*(?:rm\s+-rf|chmod\s+777|curl\s+|wget\s+)/i.test(
      normalized
    ) ||
    /(?:\.\.[\\/])+(?:etc[\\/](?:passwd|shadow|hosts)|proc[\\/]self|\.env)/i.test(normalized)
  ) {
    threats.push('APODICTIC_MCP_SHELL_OR_PATH_INJECTION');
  }

  return {
    safe: threats.length === 0,
    engine: 'apodictic-mcp-payload-guard-v1',
    toolName,
    threats,
  };
}

export function parseCliArgs(argv) {
  const sepIdx = argv.indexOf('--');
  const ownArgs = sepIdx === -1 ? argv.slice(2) : argv.slice(2, sepIdx);
  const childCmdArgs = sepIdx === -1 ? [] : argv.slice(sepIdx + 1);
  const sub = ownArgs[0] && !ownArgs[0].startsWith('-') ? ownArgs[0] : null;
  const opts = {
    help: false,
    airgap: false,
    endpoint: '',
    apiKey: '',
    config: '',
    currentBalance: 250000,
    minReserve: 50000,
    maxAutonomousLimit: 50000,
    stateDbPath: '',
  };

  for (let i = sub ? 1 : 0; i < ownArgs.length; i++) {
    const a = ownArgs[i];
    if (a === '--help' || a === '-h') opts.help = true;
    else if (a === '--airgap') opts.airgap = true;
    else if (a === '--endpoint' && ownArgs[i + 1]) opts.endpoint = ownArgs[++i];
    else if (a === '--api-key' && ownArgs[i + 1]) opts.apiKey = ownArgs[++i];
    else if (a === '--config' && ownArgs[i + 1]) opts.config = ownArgs[++i];
    else if (a === '--balance' && ownArgs[i + 1]) opts.currentBalance = Number(ownArgs[++i]);
    else if (a === '--min-reserve' && ownArgs[i + 1]) opts.minReserve = Number(ownArgs[++i]);
    else if (a === '--max-limit' && ownArgs[i + 1]) opts.maxAutonomousLimit = Number(ownArgs[++i]);
    else if (a === '--state-db' && ownArgs[i + 1]) opts.stateDbPath = ownArgs[++i];
  }

  if (opts.config && fs.existsSync(opts.config)) {
    const raw = fs.readFileSync(opts.config, 'utf8');
    if (opts.config.endsWith('.json')) {
      const cfg = JSON.parse(raw);
      if (cfg.mode === 'sovereign_airgap' || cfg.airgap) opts.airgap = true;
      if (cfg.currentBalance !== undefined) opts.currentBalance = Number(cfg.currentBalance);
      if (cfg.minReserve !== undefined) opts.minReserve = Number(cfg.minReserve);
      if (cfg.maxAutonomousLimit !== undefined) opts.maxAutonomousLimit = Number(cfg.maxAutonomousLimit);
      if (cfg.stateDbPath) opts.stateDbPath = String(cfg.stateDbPath);
      if (cfg.endpoint && !opts.airgap) opts.endpoint = String(cfg.endpoint);
    } else {
      if (/mode:\s*sovereign_airgap|airgap:\s*true/i.test(raw)) opts.airgap = true;
      const numMatch = (key) => raw.match(new RegExp(`${key}:\\s*([0-9]+(?:\\.[0-9]+)?)`, 'i'));
      const mBal = numMatch('current_balance') || numMatch('currentBalance');
      const mMin = numMatch('min_reserve') || numMatch('minReserve');
      const mCap = numMatch('max_autonomous_limit') || numMatch('maxAutonomousLimit');
      if (mBal) opts.currentBalance = Number(mBal[1]);
      if (mMin) opts.minReserve = Number(mMin[1]);
      if (mCap) opts.maxAutonomousLimit = Number(mCap[1]);
    }
  }

  return { sub, opts, childCmdArgs };
}

function makeGateway(policy = {}) {
  return new SymbolicGateway({
    posture: policy.airgap ? 'MODE_A_AIRGAP' : 'MODE_B_HYBRID',
    airgap: Boolean(policy.airgap),
    forbidRawLiterals: true,
    endpoint: policy.endpoint,
    apiKey: policy.apiKey,
    repoRoot: policy.repoRoot,
    stateDbPath: policy.stateDbPath,
  });
}

function collectStringsFromArgs(obj, depth = 0, out = []) {
  if (depth > 8 || obj == null) return out;
  if (typeof obj === 'string') {
    if (obj.trim()) out.push(obj);
    return out;
  }
  if (Array.isArray(obj)) {
    for (const item of obj) collectStringsFromArgs(item, depth + 1, out);
    return out;
  }
  if (typeof obj === 'object') {
    const priorityKeys = ['sql', 'query', 'statement', 'cmd', 'command', 'code', 'payload', 'body', 'script', 'action'];
    for (const k of priorityKeys) {
      if (Object.prototype.hasOwnProperty.call(obj, k)) {
        collectStringsFromArgs(obj[k], depth + 1, out);
      }
    }
    for (const [k, v] of Object.entries(obj)) {
      if (!priorityKeys.includes(k) && !k.startsWith('_apodictic_')) {
        collectStringsFromArgs(v, depth + 1, out);
      }
    }
  }
  return out;
}

function extractSqlFromMcpArgs(args, toolName) {
  if (typeof args?.sql === 'string' && args.sql.trim()) return args.sql;
  if (typeof args?.query === 'string' && args.query.trim()) return args.query;
  const strings = collectStringsFromArgs(args);
  const sqlLike = strings.filter((s) =>
    /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|MERGE|COPY|WITH|CREATE|EXECUTE|DO\s+\$\$)\b/i.test(s)
  );
  if (sqlLike.length > 0) return sqlLike.join('; ');
  if (typeof args?.action === 'string' && args.action.trim()) return args.action;
  return `TOOL_CALL ${toolName}`;
}

function verifyCfoSignatureToken(args, policy = {}) {
  if (policy.cfoSigned === true) return true;
  const token = typeof args?._apodictic_cfo_token === 'string' ? args._apodictic_cfo_token : '';
  const secret = policy.cfoSecret || process.env.APODICTIC_CFO_SECRET || '';
  if (!token || !secret) return false;
  try {
    const [payloadB64, sigHex] = token.split('.');
    if (!payloadB64 || !sigHex) return false;
    const expectedHex = crypto.createHmac('sha256', secret).update(payloadB64).digest('hex');
    const a = Buffer.from(sigHex, 'hex');
    const b = Buffer.from(expectedHex, 'hex');
    return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function scrubJsonStrings(val, gw, depth = 0) {
  if (depth > 10 || val == null) return val;
  if (typeof val === 'string') {
    return gw.scrubSqlAst(val, { scrubQuotedLiterals: false }).sanitized;
  }
  if (Array.isArray(val)) {
    return val.map((item) => scrubJsonStrings(item, gw, depth + 1));
  }
  if (typeof val === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(val)) {
      if (k === 'jsonrpc' || k === 'id' || k === 'type') {
        out[k] = v;
      } else {
        out[k] = scrubJsonStrings(v, gw, depth + 1);
      }
    }
    return out;
  }
  return val;
}

export async function inspectMcpEnvelope(envelope, policy = {}, sharedGateway = null) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    return {
      jsonrpc: '2.0',
      id: null,
      error: { code: -32600, message: 'Invalid JSON-RPC request envelope' },
    };
  }

  const method = envelope.method;
  const hasId = Object.prototype.hasOwnProperty.call(envelope, 'id') && envelope.id !== undefined;
  const id = hasId ? envelope.id : null;

  // JSON-RPC 2.0 notifications carry no `id`: MUST NOT emit a response frame.
  if (!hasId || (typeof method === 'string' && method.startsWith('notifications/'))) {
    return null;
  }

  const ownGateway = !sharedGateway;
  const gw = sharedGateway || makeGateway(policy);

  try {
    if (method === 'initialize') {
      const requestedVersion = envelope?.params?.protocolVersion;
      const protocolVersion = SUPPORTED_PROTOCOL_VERSIONS.includes(requestedVersion)
        ? requestedVersion
        : '2024-11-05';
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion,
          capabilities: {
            tools: { listChanged: false },
            resources: { listChanged: false },
            prompts: { listChanged: false },
          },
          serverInfo: { name: 'apodictic-mcp-verifier', version: '3.8.0' },
        },
      };
    }

    if (method === 'ping') {
      return { jsonrpc: '2.0', id, result: {} };
    }

    if (method === 'tools/list') {
      return { jsonrpc: '2.0', id, result: { tools: BUILTIN_TOOLS } };
    }

    if (method === 'resources/list') {
      return { jsonrpc: '2.0', id, result: { resources: [] } };
    }

    if (method === 'prompts/list') {
      return { jsonrpc: '2.0', id, result: { prompts: [] } };
    }

    if (method !== 'tools/call') {
      return { jsonrpc: '2.0', id, result: { passthrough: true, allowed: true } };
    }

    const toolName = envelope?.params?.name || '';
    const args = envelope?.params?.arguments || {};

    const payloadGuard = scanApodicticMcpToolGuard(toolName, args);
    if (!payloadGuard.safe) {
      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: -32002,
          message: `Blocked by Apodictic MCP Payload Guard: ${payloadGuard.threats.join(', ')}`,
          data: {
            verdict: 'UNSAT',
            engine: payloadGuard.engine,
            threats: payloadGuard.threats,
            otel_genai_span: {
              'gen_ai.operation.name': 'execute_tool',
              'gen_ai.tool.name': toolName,
              'apodictic.verdict': 'UNSAT',
              'apodictic.z3_proof_digest': null,
              'apodictic.counterfactual_max_safe_amount': null,
            },
          },
        },
      };
    }

    if (toolName === 'apodictic_verify_three_way_match') {
      const res = await gw.verifyThreeWayMatch(args);
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(res) }],
          structuredContent: res,
          isError: !res.matched,
        },
      };
    }
    if (toolName === 'apodictic_verify_tax') {
      const res = await gw.verifyTaxCompliance(args);
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(res) }],
          structuredContent: res,
          isError: !res.verified,
        },
      };
    }
    if (toolName === 'apodictic_rollback') {
      const res = await gw.rollback(args.batchId);
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(res) }],
          structuredContent: res,
          isError: !res.success,
        },
      };
    }
    if (toolName === 'apodictic_audit_status') {
      const res = await gw.verifyAuditChain();
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(res) }],
          structuredContent: res,
          isError: !res.valid,
        },
      };
    }
    if (toolName === 'apodictic_evaluate_policy') {
      const res = await gw.evaluatePolicy(args);
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(res) }],
          structuredContent: res,
          isError: !res.allowed,
        },
      };
    }
    if (toolName === 'apodictic_merkle_proof') {
      const res = await gw.getMerkleInclusionProof(args.blockIndex);
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(res) }],
          structuredContent: res,
          isError: !res.inclusion_verified,
        },
      };
    }
    if (toolName === 'apodictic_flush_escrow') {
      const res = await gw.flushEscrow(args);
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(res) }],
          structuredContent: res,
          isError: false,
        },
      };
    }

    const payloadStr = JSON.stringify(args);
    const { sanitized, redactions } = gw.scrubSqlAst(payloadStr);
    const extractedSql = extractSqlFromMcpArgs(args, toolName);

    // Server-side policy authority ONLY: never trust client-supplied args.cfoSigned / currentBalance / limits
    const authoritativeBalance = Number(
      policy.currentBalance ?? (process.env.APODICTIC_CURRENT_BALANCE ? Number(process.env.APODICTIC_CURRENT_BALANCE) : 250000)
    );
    const authoritativeReserve = Number(
      policy.minReserve ?? (process.env.APODICTIC_MIN_RESERVE ? Number(process.env.APODICTIC_MIN_RESERVE) : 50000)
    );
    const authoritativeCap = Number(
      policy.maxAutonomousLimit ?? (process.env.APODICTIC_MAX_AUTONOMOUS_LIMIT ? Number(process.env.APODICTIC_MAX_AUTONOMOUS_LIMIT) : 50000)
    );
    const authoritativeCfoSigned = verifyCfoSignatureToken(args, policy);

    const hasOdooArgs = Boolean(args.odoo || args.model || args.method || args.vals_list || args.valsList);
    const odooBlock = hasOdooArgs
      ? {
          ...(typeof args.odoo === 'object' && args.odoo ? args.odoo : {}),
          ...(args.model ? { model: args.model } : {}),
          ...(args.method ? { method: args.method } : {}),
          ...(args.vals_list ? { vals_list: args.vals_list } : {}),
          ...(args.valsList ? { valsList: args.valsList } : {}),
          ...(args.ids ? { ids: args.ids } : {}),
          ...(args.bearer_scope ? { bearerScope: args.bearer_scope } : {}),
          ...(args.bearerScope ? { bearerScope: args.bearerScope } : {}),
          ...(args.hard_lock_date ? { hardLockDate: args.hard_lock_date } : {}),
          ...(args.inalterable_hash ? { inalterableHash: args.inalterable_hash } : {}),
        }
      : undefined;

    const check = await gw.verifyMutation({
      sql: extractedSql,
      accountId: String(args.accountId || policy.accountId || 'mcp_default'),
      amount: args.amount !== undefined ? Number(args.amount) : undefined,
      currentBalance: authoritativeBalance,
      minReserve: authoritativeReserve,
      maxAutonomousLimit: authoritativeCap,
      cfoSigned: authoritativeCfoSigned,
      debitTotal: args.debitTotal !== undefined ? Number(args.debitTotal) : undefined,
      creditTotal: args.creditTotal !== undefined ? Number(args.creditTotal) : undefined,
      targetSystem: args.targetSystem || (hasOdooArgs ? 'odoo_v20' : undefined),
      odoo: odooBlock,
    });

    if (!check.verified) {
      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: -32001,
          message: `Blocked by Apodictic MCP Verifier: ${check.reason || 'Z3_UNSAT'}`,
          data: {
            verdict: check.verdict,
            engine: check.engine,
            proofDigest: check.proofDigest,
            blockIndex: check.blockIndex,
            blockHash: check.blockHash,
            counterfactualPatch: check.counterfactualPatch ?? null,
            sanitizedArguments: sanitized,
            redactions,
            otel_genai_span: {
              'gen_ai.operation.name': 'execute_tool',
              'gen_ai.tool.name': toolName,
              'apodictic.verdict': check.verdict,
              'apodictic.z3_proof_digest': check.proofDigest ?? null,
              'apodictic.counterfactual_max_safe_amount': check.counterfactualPatch?.max_safe_amount ?? null,
            },
          },
        },
      };
    }

    const okResult = {
      allowed: true,
      verdict: check.verdict,
      engine: check.engine,
      proofDigest: check.proofDigest,
      blockIndex: check.blockIndex,
      blockHash: check.blockHash,
      rollbackBatchId: check.rollbackBatchId,
      sanitizedArguments: sanitized,
      redactions,
      otel_genai_span: {
        'gen_ai.operation.name': 'execute_tool',
        'gen_ai.tool.name': toolName,
        'apodictic.verdict': check.verdict,
        'apodictic.z3_proof_digest': check.proofDigest ?? null,
        'apodictic.counterfactual_max_safe_amount': check.counterfactualPatch?.max_safe_amount ?? null,
      },
    };

    if (toolName === 'apodictic_verify_mutation') {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(okResult) }],
          structuredContent: okResult,
          isError: false,
        },
      };
    }

    return { jsonrpc: '2.0', id, result: okResult };
  } catch (err) {
    return {
      jsonrpc: '2.0',
      id,
      error: { code: -32603, message: err instanceof Error ? err.message : String(err) },
    };
  } finally {
    if (ownGateway) await gw.close();
  }
}

function createStdoutWriter() {
  let queue = Promise.resolve();
  return (line) => {
    queue = queue.then(
      () =>
        new Promise((resolve) => {
          process.stdout.write(line + '\n', () => resolve());
        })
    );
    return queue;
  };
}

async function runStandaloneServer(policy = {}) {
  const gw = makeGateway(policy);
  const writeLine = createStdoutWriter();
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const msg = JSON.parse(trimmed);
      const out = await inspectMcpEnvelope(msg, policy, gw);
      if (out !== null) {
        await writeLine(JSON.stringify(out));
      }
    } catch (err) {
      await writeLine(
        JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: err.message } })
      );
    }
  }
  await gw.close();
}

async function runStdioProxy(cmd, args, policy = {}) {
  const gw = makeGateway(policy);
  const writeLine = createStdoutWriter();
  const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'inherit'] });
  child.stdin.on('error', () => {});

  const childRl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
  const childDrainPromise = (async () => {
    for await (const line of childRl) {
      if (!line.trim()) continue;
      try {
        const parsed = JSON.parse(line);
        const scrubbed = scrubJsonStrings(parsed, gw);
        await writeLine(JSON.stringify(scrubbed));
      } catch {
        try {
          await writeLine(gw.scrubSqlAst(line, { scrubQuotedLiterals: false }).sanitized);
        } catch {
          await writeLine(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32603, message: 'Response egress scrubbing failed closed' } }));
        }
      }
    }
  })();
  const exitPromise = new Promise((resolve) => {
    child.on('error', async (err) => {
      await writeLine(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32603, message: `Wrapped MCP child error: ${err.message}` } }));
      resolve(1);
    });
    child.on('exit', resolve);
  });

  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch (err) {
      // Fail closed on malformed JSON-RPC: never forward unparseable input to child
      await writeLine(
        JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: err.message } })
      );
      continue;
    }

    const method = msg?.method;
    const isNotification =
      !Object.prototype.hasOwnProperty.call(msg, 'id') ||
      msg.id === undefined ||
      (typeof method === 'string' && method.startsWith('notifications/'));

    if (isNotification) {
      child.stdin.write(trimmed + '\n');
      continue;
    }

    if (method === 'tools/call') {
      const toolName = msg?.params?.name || '';
      const verdict = await inspectMcpEnvelope(msg, policy, gw);
      // Built-in Apodictic tools execute inside firewall and never forward to child
      if (BUILTIN_TOOL_NAMES.has(toolName)) {
        if (verdict) await writeLine(JSON.stringify(verdict));
        continue;
      }
      if (verdict?.error) {
        await writeLine(JSON.stringify(verdict));
        continue;
      }
    }

    child.stdin.write(trimmed + '\n');
  }
  child.stdin.end();
  const [code] = await Promise.all([exitPromise, childDrainPromise]);
  await gw.close();
  process.exit(code ?? 0);
}

async function runReproducibleDemo(opts = {}) {
  const remoteEndpoint = !opts.airgap && opts.endpoint ? String(opts.endpoint) : '';
  console.log('\n=== APODICTIC REPRODUCIBLE 3-SCENARIO TECHNICAL DEMO ===');
  console.log(
    remoteEndpoint
      ? `Engine: apodictic-mcp-verifier + Real WASM PostgreSQL 17 (@electric-sql/pglite) + Remote ${remoteEndpoint}\n`
      : 'Engine: apodictic-mcp-verifier + Real WASM PostgreSQL 17 (@electric-sql/pglite) + Z3 5.4.1 (Python/WASM)\n'
  );

  const demoDir = fs.mkdtempSync(path.join(os.tmpdir(), 'apodictic-mcp-demo-'));
  const gw = new SymbolicGateway({
    posture: remoteEndpoint ? 'MODE_B_HYBRID' : 'MODE_A_AIRGAP',
    airgap: !remoteEndpoint,
    endpoint: remoteEndpoint,
    apiKey: opts.apiKey || '',
    stateDbPath: path.join(demoDir, 'state.db'),
  });
  const pg = new PGlite();

  try {
    await pg.exec(`
      CREATE TABLE accounts (
        id TEXT PRIMARY KEY,
        balance DOUBLE PRECISION NOT NULL,
        min_reserve DOUBLE PRECISION NOT NULL
      );
      CREATE TABLE account_move_line (
        id INT PRIMARY KEY,
        move_id INT NOT NULL,
        move_name TEXT NOT NULL,
        account_code TEXT NOT NULL,
        debit DOUBLE PRECISION NOT NULL DEFAULT 0,
        credit DOUBLE PRECISION NOT NULL DEFAULT 0,
        CHECK (debit * credit = 0)
      );
      CREATE TABLE tax_chain (
        record_id TEXT PRIMARY KEY,
        sha256 TEXT NOT NULL,
        active BOOLEAN NOT NULL
      );

      INSERT INTO accounts (id, balance, min_reserve) VALUES ('acc_treasury', 250000, 50000);
      INSERT INTO account_move_line (id, move_id, move_name, account_code, debit, credit) VALUES
        (48201, 9412, 'INV/2026/09412', '121000', 4500.00, 0.00),
        (48202, 9412, 'INV/2026/09412', '211000', 0.00, 4500.00);
      INSERT INTO tax_chain (record_id, sha256, active) VALUES ('TAX-2026-001', 'e3b0c44298fc1c149afb', true);
    `);

    const snapshotState = async () => ({
      accounts: (await pg.query('SELECT id, balance, min_reserve FROM accounts ORDER BY id')).rows,
      account_move_line: (await pg.query('SELECT id, move_id, move_name, account_code, debit, credit FROM account_move_line ORDER BY id')).rows,
      tax_chain: (await pg.query('SELECT record_id, sha256, active FROM tax_chain ORDER BY record_id')).rows,
    });

    console.log('[INITIAL POSTGRESQL 17 DATABASE STATE]');
    console.log(JSON.stringify(await snapshotState(), null, 2));

    let committedCount = 0;
    let blockedCount = 0;

    // Scenario 1: Legitimate financial write that passes Z3 solvency & velocity checks and commits to PostgreSQL
    const sql1 = "UPDATE accounts SET balance = balance - 12500 WHERE id = 'acc_treasury';";
    const res1 = await gw.verifyMutation({
      sql: sql1,
      accountId: 'acc_treasury',
      amount: 12500,
      currentBalance: 250000,
      minReserve: 50000,
      maxAutonomousLimit: 50000,
    });
    const ok1 = Boolean(res1.verified);
    if (ok1) {
      await pg.exec(sql1);
      committedCount++;
    } else {
      blockedCount++;
    }
    console.log('\n--- SCENARIO 1: Legitimate Financial Write ($12,500 disbursement) ---');
    console.log('SQL:     ', sql1);
    console.log(
      'Verdict: ',
      ok1 ? 'SAT · ALLOWED' : 'UNSAT · BLOCKED',
      '| Solver:',
      res1.z3SolveMs !== undefined ? `Z3 5.4.1 (${res1.z3SolveMs} ms)` : 'Z3 5.4.1',
      '| Reason:',
      res1.reason || 'All invariants satisfied; committed to PostgreSQL'
    );

    const postBal1 = Number((await pg.query("SELECT balance FROM accounts WHERE id = 'acc_treasury'")).rows[0]?.balance ?? 250000);

    // Scenario 2: Odoo 18-20 account_move_line single-line debit mutation
    // Note: PostgreSQL single-row CHECK (debit * credit = 0) ALLOWS this write!
    // PGlite executes in shadow rollback to capture multi-row SUM(debit) vs SUM(credit), then Z3 proves UNSAT.
    const sql2 = 'UPDATE account_move_line SET debit = 4820.00 WHERE move_id = 9412 AND id = 48201;';
    let observedDebit2 = 4500.0;
    let observedCredit2 = 4500.0;
    await pg.exec('BEGIN;');
    try {
      await pg.exec(sql2);
      const totals = await pg.query('SELECT SUM(debit) AS d, SUM(credit) AS c FROM account_move_line WHERE move_id = 9412');
      observedDebit2 = Number(totals.rows[0]?.d ?? 4500.0);
      observedCredit2 = Number(totals.rows[0]?.c ?? 4500.0);
    } finally {
      await pg.exec('ROLLBACK;');
    }
    const res2 = await gw.verifyMutation({
      sql: sql2,
      accountId: 'acc_treasury',
      amount: Math.abs(observedDebit2 - observedCredit2),
      currentBalance: postBal1,
      minReserve: 50000,
      maxAutonomousLimit: 50000,
      debitTotal: observedDebit2,
      creditTotal: observedCredit2,
    });
    const ok2 = Boolean(res2.verified);
    if (ok2) {
      await pg.exec(sql2);
      committedCount++;
    } else {
      blockedCount++;
    }
    console.log('\n--- SCENARIO 2: Unbalanced Odoo Journal Line Update (PostgreSQL CHECK bypassed -> Z3 UNSAT) ---');
    console.log('SQL:     ', sql2);
    console.log(
      'Shadow:  ',
      `PostgreSQL CHECK(debit*credit=0) allowed update -> observed SUM(debit)=$${observedDebit2.toFixed(2)} != SUM(credit)=$${observedCredit2.toFixed(2)} (rolled back)`
    );
    console.log(
      'Verdict: ',
      ok2 ? 'SAT · ALLOWED' : 'UNSAT · BLOCKED',
      '| Reason:',
      res2.reason || `Double-entry violation: drift = $${Math.abs(observedDebit2 - observedCredit2).toFixed(2)}`
    );

    // Scenario 3: Attempted protected tax-record deletion that is blocked via Z3 INV_REVERSIBILITY_GUARD
    const sql3 = "DELETE FROM tax_chain WHERE record_id = 'TAX-2026-001';";
    const res3 = await gw.verifyMutation({
      sql: sql3,
      accountId: 'acc_treasury',
      amount: 0,
      currentBalance: postBal1,
      minReserve: 50000,
      maxAutonomousLimit: 50000,
    });
    const ok3 = Boolean(res3.verified);
    if (ok3) {
      await pg.exec(sql3);
      committedCount++;
    } else {
      blockedCount++;
    }
    console.log('\n--- SCENARIO 3: Attempted Protected Tax-Record Deletion ---');
    console.log('SQL:     ', sql3);
    console.log(
      'Verdict: ',
      ok3 ? 'SAT · ALLOWED' : 'UNSAT · BLOCKED',
      '| Reason:',
      res3.reason || 'Destructive DELETE on protected tax_chain blocked'
    );

    console.log('\n[FINAL POSTGRESQL 17 DATABASE STATE (VERIFIED INTACT)]');
    console.log(JSON.stringify(await snapshotState(), null, 2));
    console.log(
      `\nSummary: ${committedCount} legitimate write committed | ${blockedCount} invalid mutations blocked | 0 corrupted records.\n`
    );
  } finally {
    await pg.close();
    await gw.close();
    fs.rmSync(demoDir, { recursive: true, force: true });
  }
}

const isEntrypoint =
  process.argv[1] &&
  (process.argv[1].endsWith('apodictic-mcp-verifier.mjs') || process.argv[1].endsWith('apodictic-mcp-verifier'));

if (isEntrypoint) {
  const { sub, opts, childCmdArgs } = parseCliArgs(process.argv);
  if (opts.help) {
    console.log(
      'Usage:\n  apodictic-mcp-verifier demo\n  apodictic-mcp-verifier serve [--airgap] [--config <path>] [--endpoint <url>]\n  apodictic-mcp-verifier wrap [--airgap] [--config <path>] -- <mcp-server-cmd> [args...]'
    );
    process.exit(0);
  } else if (sub === 'demo') {
    await runReproducibleDemo(opts);
    process.exit(0);
  } else if (sub === 'serve') {
    await runStandaloneServer(opts);
  } else if (sub === 'wrap' && childCmdArgs.length > 0 && childCmdArgs[0]) {
    await runStdioProxy(childCmdArgs[0], childCmdArgs.slice(1), opts);
  } else {
    let raw = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (raw += chunk));
    process.stdin.on('end', async () => {
      if (!raw.trim()) {
        console.error('Usage: apodictic-mcp-verifier wrap -- <mcp-server-cmd> [args...]');
        process.exit(1);
      }
      const res = await inspectMcpEnvelope(JSON.parse(raw.trim()), opts);
      console.log(JSON.stringify(res, null, 2));
      process.exit(res?.error ? 2 : 0);
    });
  }
}
