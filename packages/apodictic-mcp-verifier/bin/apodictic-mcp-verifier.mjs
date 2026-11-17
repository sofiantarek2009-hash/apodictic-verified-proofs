#!/usr/bin/env node
/**
 * @apodictic/mcp-verifier
 * Production MCP JSON-RPC 2.0 firewall & verification server.
 *
 * Modes:
 *   1. `apodictic-mcp-verifier serve`
 *      Standalone MCP stdio server exposing Z3 5.4.1 verification, 3-way match,
 *      indirect tax parity, atomic rollback, and WORM audit tools.
 *   2. `apodictic-mcp-verifier wrap -- <command> [args...]`
 *      Drop-in stateful firewall proxy in front of any MCP server (Postgres, Odoo, Stripe).
 *   3. Single-shot stdin envelope check.
 */
import { spawn } from 'node:child_process';
import readline from 'node:readline';

let SymbolicGateway;
try {
  ({ SymbolicGateway } = await import('@apodictic/sdk'));
} catch {
  ({ SymbolicGateway } = await import('../../apodictic-sdk/src/index.mjs'));
}

const BUILTIN_TOOLS = [
  {
    name: 'apodictic_verify_mutation',
    description: 'Verify SQL or ERP mutation against Z3 5.4.1 solvency, cap, tax, and destructive-op invariants prior to commit.',
    inputSchema: {
      type: 'object',
      properties: {
        sql: { type: 'string' },
        accountId: { type: 'string' },
        amount: { type: 'number' },
        currentBalance: { type: 'number' },
        minReserve: { type: 'number' },
        maxAutonomousLimit: { type: 'number' },
        cfoSigned: { type: 'boolean' },
      },
      required: ['sql'],
    },
  },
  {
    name: 'apodictic_verify_three_way_match',
    description: 'Verify Purchase Order <-> Goods Receipt <-> Vendor Invoice parity with Z3.',
    inputSchema: { type: 'object', required: ['po', 'receipts', 'invoices'] },
  },
  {
    name: 'apodictic_verify_tax',
    description: 'Verify Egypt ETA (14%) / KSA ZATCA (15%) / EU VAT statutory tax parity.',
    inputSchema: { type: 'object', required: ['jurisdiction', 'lines'] },
  },
  {
    name: 'apodictic_rollback',
    description: 'Execute atomic <38ms local rollback for a staged batchId.',
    inputSchema: { type: 'object', properties: { batchId: { type: 'string' } }, required: ['batchId'] },
  },
  {
    name: 'apodictic_audit_status',
    description: 'Verify full 256-bit SHA-256 WORM Merkle audit chain integrity.',
    inputSchema: { type: 'object' },
  },
];

export async function inspectMcpEnvelope(envelope, policy = {}, sharedGateway = null) {
  const ownGateway = !sharedGateway;
  const gw =
    sharedGateway ||
    new SymbolicGateway({
      posture: 'MODE_B_HYBRID',
      forbidRawLiterals: true,
      endpoint: policy.endpoint,
      apiKey: policy.apiKey,
      repoRoot: policy.repoRoot,
    });

  try {
    const method = envelope?.method;
    const id = envelope?.id ?? null;

    if (method === 'initialize') {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'apodictic-mcp-verifier', version: '3.8.0' },
        },
      };
    }

    if (method === 'tools/list') {
      return { jsonrpc: '2.0', id, result: { tools: BUILTIN_TOOLS } };
    }

    if (method !== 'tools/call') {
      return { jsonrpc: '2.0', id, result: { passthrough: true, allowed: true } };
    }

    const toolName = envelope?.params?.name || '';
    const args = envelope?.params?.arguments || {};

    if (toolName === 'apodictic_verify_three_way_match') {
      const res = await gw.verifyThreeWayMatch(args);
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(res) }], structuredContent: res } };
    }
    if (toolName === 'apodictic_verify_tax') {
      const res = await gw.verifyTaxCompliance(args);
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(res) }], structuredContent: res } };
    }
    if (toolName === 'apodictic_rollback') {
      const res = await gw.rollback(args.batchId);
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(res) }], structuredContent: res } };
    }
    if (toolName === 'apodictic_audit_status') {
      const res = await gw.verifyAuditChain();
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(res) }], structuredContent: res } };
    }

    const payloadStr = JSON.stringify(args);
    const { sanitized, redactions } = gw.scrubSqlAst(payloadStr);

    const check = await gw.verifyMutation({
      sql: String(args.sql || args.query || args.action || `TOOL_CALL ${toolName}`),
      accountId: String(args.accountId || policy.accountId || 'mcp_default'),
      amount: args.amount !== undefined ? Number(args.amount) : undefined,
      currentBalance: Number(args.currentBalance ?? policy.currentBalance ?? 250000),
      minReserve: Number(args.minReserve ?? policy.minReserve ?? 50000),
      maxAutonomousLimit: Number(args.maxAutonomousLimit ?? policy.maxAutonomousLimit ?? 50000),
      cfoSigned: Boolean(args.cfoSigned),
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
            sanitizedArguments: sanitized,
            redactions,
          },
        },
      };
    }

    return {
      jsonrpc: '2.0',
      id,
      result: {
        allowed: true,
        verdict: check.verdict,
        engine: check.engine,
        proofDigest: check.proofDigest,
        blockIndex: check.blockIndex,
        blockHash: check.blockHash,
        rollbackBatchId: check.rollbackBatchId,
        sanitizedArguments: sanitized,
        redactions,
      },
    };
  } finally {
    if (ownGateway) await gw.close();
  }
}

async function runStandaloneServer() {
  const gw = new SymbolicGateway({ posture: 'MODE_B_HYBRID', forbidRawLiterals: true });
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const msg = JSON.parse(trimmed);
      const out = await inspectMcpEnvelope(msg, {}, gw);
      process.stdout.write(JSON.stringify(out) + '\n');
    } catch (err) {
      process.stdout.write(
        JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: err.message } }) + '\n'
      );
    }
  }
  await gw.close();
}

async function runStdioProxy(cmd, args) {
  const gw = new SymbolicGateway({ posture: 'MODE_B_HYBRID', forbidRawLiterals: true });
  const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'inherit'] });
  child.stdout.on('data', (chunk) => process.stdout.write(chunk));
  const exitPromise = new Promise((resolve) => child.on('exit', resolve));

  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const msg = JSON.parse(trimmed);
      if (msg.method === 'tools/call') {
        const verdict = await inspectMcpEnvelope(msg, {}, gw);
        if (verdict.error) {
          process.stdout.write(JSON.stringify(verdict) + '\n');
          continue;
        }
      }
      child.stdin.write(trimmed + '\n');
    } catch {
      child.stdin.write(trimmed + '\n');
    }
  }
  child.stdin.end();
  const code = await exitPromise;
  await gw.close();
  process.exit(code ?? 0);
}

if (process.argv[1] && process.argv[1].endsWith('apodictic-mcp-verifier.mjs')) {
  const sub = process.argv[2];
  const sepIdx = process.argv.indexOf('--');
  if (sub === '--help' || sub === '-h') {
    console.log('Usage:\n  apodictic-mcp-verifier serve\n  apodictic-mcp-verifier wrap -- <mcp-server-cmd> [args...]');
    process.exit(0);
  } else if (sub === 'serve') {
    await runStandaloneServer();
  } else if (sub === 'wrap' && sepIdx !== -1 && process.argv[sepIdx + 1]) {
    await runStdioProxy(process.argv[sepIdx + 1], process.argv.slice(sepIdx + 2));
  } else {
    let raw = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (raw += chunk));
    process.stdin.on('end', async () => {
      if (!raw.trim()) {
        console.error('Usage: apodictic-mcp-verifier wrap -- <mcp-server-cmd> [args...]');
        process.exit(1);
      }
      const res = await inspectMcpEnvelope(JSON.parse(raw.trim()));
      console.log(JSON.stringify(res, null, 2));
      process.exit(res.error ? 2 : 0);
    });
  }
}
