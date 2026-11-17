import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectMcpEnvelope } from './bin/apodictic-mcp-verifier.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, 'bin', 'apodictic-mcp-verifier.mjs');

// 1. Direct Z3 5.4.1 envelope check (cap bypass blocked + IBAN scrubbed)
const blocked = await inspectMcpEnvelope({
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/call',
  params: {
    name: 'odoo_payout',
    arguments: {
      sql: 'UPDATE vendor_disbursements SET amount=75000 WHERE id=4092;',
      amount: 75000,
      maxAutonomousLimit: 50000,
      cfoSigned: false,
      iban: 'DE89370400440532013000',
    },
  },
});
assert.ok(blocked.error && blocked.error.code === -32001);
assert.equal(blocked.error.data.engine, 'apodictic-local-z3-5.4.1');
assert.match(blocked.error.data.proofDigest, /^[a-f0-9]{64}$/);
assert(!blocked.error.data.sanitizedArguments.includes('DE89370400440532013000'));

// 2. End-to-end stdio `wrap --` proxy test: stateful multi-turn smurfing + DROP block
const childScript = `
const rl = require('readline').createInterface({ input: process.stdin });
rl.on('line', (l) => {
  const m = JSON.parse(l);
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { executedByChild: true } }) + '\\n');
});
`;

const outputs = await new Promise((resolve, reject) => {
  const proc = spawn('node', [BIN, 'wrap', '--', 'node', '-e', childScript], { stdio: ['pipe', 'pipe', 'pipe'] });
  const lines = [];
  proc.stdout.on('data', (d) => lines.push(...d.toString().trim().split('\n').filter(Boolean)));
  proc.on('error', reject);
  proc.on('close', () => resolve(lines.map((l) => JSON.parse(l))));

  // Turn 1: Unbounded DELETE without WHERE -> must block before child
  proc.stdin.write(JSON.stringify({
    jsonrpc: '2.0', id: 10, method: 'tools/call',
    params: { name: 'pg_exec', arguments: { sql: 'DELETE FROM account_move;' } },
  }) + '\n');
  // Turn 2: Smurfing split 1 ($40k < $50k cap) -> allowed to child
  proc.stdin.write(JSON.stringify({
    jsonrpc: '2.0', id: 11, method: 'tools/call',
    params: { name: 'pg_exec', arguments: { sql: 'UPDATE vendor_disbursements SET amount=40000 WHERE id=1;', accountId: 'mcp_smurf', amount: 40000, maxAutonomousLimit: 50000, cfoSigned: false } },
  }) + '\n');
  // Turn 3: Smurfing split 2 ($40k on same account -> cumulative $80k > $50k) -> blocked!
  proc.stdin.write(JSON.stringify({
    jsonrpc: '2.0', id: 12, method: 'tools/call',
    params: { name: 'pg_exec', arguments: { sql: 'UPDATE vendor_disbursements SET amount=40000 WHERE id=2;', accountId: 'mcp_smurf', amount: 40000, maxAutonomousLimit: 50000, cfoSigned: false } },
  }) + '\n');
  proc.stdin.end();
});

assert.equal(outputs.find((m) => m.id === 10).error.code, -32001, 'DELETE bypassed proxy');
assert.equal(outputs.find((m) => m.id === 11).result.executedByChild, true, 'First valid split did not reach child');
assert.equal(outputs.find((m) => m.id === 12).error.code, -32001, 'Second smurfing split bypassed stateful cap!');

// 3. Standalone `serve` mode exposing tools/list + apodictic_audit_status
const serveOutputs = await new Promise((resolve, reject) => {
  const proc = spawn('node', [BIN, 'serve'], { stdio: ['pipe', 'pipe', 'pipe'] });
  const lines = [];
  proc.stdout.on('data', (d) => lines.push(...d.toString().trim().split('\n').filter(Boolean)));
  proc.on('error', reject);
  proc.on('close', () => resolve(lines.map((l) => JSON.parse(l))));

  proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) + '\n');
  proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'apodictic_audit_status', arguments: {} } }) + '\n');
  proc.stdin.end();
});

assert.ok(serveOutputs.find((m) => m.id === 1).result.tools.length >= 5);
assert.equal(serveOutputs.find((m) => m.id === 2).result.structuredContent.valid, true);

console.log('✓ @apodictic/mcp-verifier production Z3 + stateful smurfing proxy + serve tests passed');
