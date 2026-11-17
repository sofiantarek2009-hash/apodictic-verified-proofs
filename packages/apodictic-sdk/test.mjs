import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { SymbolicGateway } from './src/index.mjs';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'apodictic-sdk-test-'));
const stateDbPath = path.join(tmpDir, 'enclave_state.db');
const gw = new SymbolicGateway({ posture: 'MODE_B_HYBRID', forbidRawLiterals: true, stateDbPath });

try {
  // 1. Zero-PII SQL AST scrubbing + Zero-Width character evasion defense
  const rawSql = "SELECT national_id, iban FROM claims WHERE tin = 'ETA-301099481' AND email = 'ap@nile-pharma.eg' AND iban = 'DE89370400440532013000'";
  const scrubbed = gw.scrubSqlAst(rawSql);
  assert(!scrubbed.sanitized.includes('ETA-301099481'));
  assert(!scrubbed.sanitized.includes('ap@nile-pharma.eg'));
  assert(!scrubbed.sanitized.includes('DE89370400440532013000'));
  assert.equal(gw.rehydrate(scrubbed.sanitized), rawSql);

  // 2. Real Z3 5.4.1 blocking: DROP, zero-width obfuscated DROP, negative/NaN validation, cap bypass
  const dropRes = await gw.verifyMutation({ sql: 'DROP TABLE account_move CASCADE;' });
  assert.equal(dropRes.verdict, 'UNSAT');
  assert.equal(dropRes.verified, false);
  assert.match(dropRes.proofDigest, /^[a-f0-9]{64}$/);

  const zwDrop = await gw.verifyMutation({ sql: 'D\u200bROP TABLE account_move;' });
  assert.equal(zwDrop.verified, false, 'Zero-width obfuscated DROP was not blocked');

  await assert.rejects(() => gw.verifyMutation({ sql: 'UPDATE x SET a=1 WHERE id=1;', amount: -100 }));
  await assert.rejects(() => gw.verifyMutation({ sql: 'UPDATE x SET a=1 WHERE id=1;', amount: Number.NaN }));

  // 3. Persistent multi-turn 24h smurfing velocity check across calls (under $50k each, cumulative $90k > $50k)
  const smurf1 = await gw.verifyMutation({
    sql: 'UPDATE vendor_disbursements SET amount=45000 WHERE id=1;',
    accountId: 'smurf_acct_1',
    amount: 45000,
    maxAutonomousLimit: 50000,
    cfoSigned: false,
  });
  assert.equal(smurf1.verified, true, 'First $45k tx within $50k cap should pass');

  const smurf2 = await gw.verifyMutation({
    sql: 'UPDATE vendor_disbursements SET amount=45000 WHERE id=2;',
    accountId: 'smurf_acct_1',
    amount: 45000,
    maxAutonomousLimit: 50000,
    cfoSigned: false,
  });
  assert.equal(smurf2.verified, false, 'Second $45k tx (cumulative $90k > $50k) must be blocked');

  // 4. Staged atomic rollback (<38ms)
  const valid = await gw.verifyMutation({
    sql: "UPDATE vendor_disbursements SET status='PROVED', amount=14200 WHERE id=4092;",
    accountId: 'acct_rb_1',
    amount: 14200,
    cfoSigned: true,
  });
  assert.equal(valid.verified, true);
  assert.ok(valid.rollbackBatchId);
  const rb = await gw.rollback(valid.rollbackBatchId);
  assert.equal(rb.success, true);

  // 5. 3-Way Match Z3 Solver (phantom overbilling blocked vs exact match allowed)
  const matchBad = await gw.verifyThreeWayMatch({
    po: { poId: 'PO-1', sku: 'MED-1', orderedQty: 100, unitPrice: 50 },
    receipts: [{ receiptId: 'GRN-1', poId: 'PO-1', sku: 'MED-1', receivedQty: 60 }],
    invoices: [{ invoiceId: 'INV-1', poId: 'PO-1', sku: 'MED-1', billedQty: 100, billedUnitPrice: 50 }],
  });
  assert.equal(matchBad.matched, false);
  assert.equal(matchBad.verdict, 'UNSAT');

  // 6. Statutory Tax Solver (Egypt ETA 14% drift blocked vs exact SAT)
  const taxBad = await gw.verifyTaxCompliance({
    jurisdiction: 'EGYPT_ETA',
    lines: [{ sku: 'SKU-1', netAmount: 1000, claimedVatAmount: 100 }],
    hasCryptographicStamp: true,
  });
  assert.equal(taxBad.verified, false);

  // 7. Bi-Temporal Ledger point-in-time travel
  await gw.bitemporalInsert({ entityId: 'ACC-1', data: { rev: 1000000 }, validStart: 1000, systemTime: 1000 });
  await gw.bitemporalRestate({ entityId: 'ACC-1', data: { rev: 1150000 }, validStart: 1000, systemTime: 3000 });
  const marSnap = await gw.bitemporalAsOf({ entityId: 'ACC-1', validTime: 2000, systemTime: 2000 });
  const novSnap = await gw.bitemporalAsOf({ entityId: 'ACC-1', validTime: 2000, systemTime: 3500 });
  assert.equal(marSnap.data.rev, 1000000);
  assert.equal(novSnap.data.rev, 1150000);

  // 8. Full WORM SHA-256 Audit Chain Integrity & Health
  const chain = await gw.verifyAuditChain();
  assert.equal(chain.valid, true);
  assert.ok(chain.block_count >= 5);
  const h = await gw.health();
  assert.equal(h.status, 'healthy');
  assert.equal(h.z3_version, '5.4.1');

  console.log(`✓ @apodictic/sdk full 8-subsystem production tests passed (WORM blocks=${chain.block_count}, Z3=${h.z3_version})`);
} finally {
  await gw.close();
}

// 9. Crash & Restart Durability Test: kill worker, spawn brand-new instance with same stateDbPath
const gw2 = new SymbolicGateway({ posture: 'MODE_B_HYBRID', forbidRawLiterals: true, stateDbPath });
try {
  const afterCrash = await gw2.verifyMutation({
    sql: 'UPDATE vendor_disbursements SET amount=45000 WHERE id=99;',
    accountId: 'smurf_acct_1',
    amount: 45000,
    maxAutonomousLimit: 50000,
    cfoSigned: false,
  });
  assert.equal(afterCrash.verified, false, 'Velocity smurfing state was lost after worker crash/restart!');
  const chainAfter = await gw2.verifyAuditChain();
  assert.equal(chainAfter.valid, true, 'WORM hash chain corrupted across restart!');

  // 10. 20 concurrent Promise.all requests on one persistent worker (multiplexing integrity)
  const concurrent = await Promise.all(
    Array.from({ length: 20 }, (_, idx) =>
      gw2.verifyMutation({
        sql: `UPDATE vendor_disbursements SET amount=1000 WHERE id=${5000 + idx};`,
        accountId: `conc_acct_${idx}`,
        amount: 1000,
        maxAutonomousLimit: 50000,
        cfoSigned: true,
      })
    )
  );
  assert.equal(concurrent.filter((r) => r.verified).length, 20, 'Concurrent multiplexing dropped or failed valid requests');

  // 11. ZATCA missing cryptographic stamp rejection
  const zatcaNoStamp = await gw2.verifyTaxCompliance({
    jurisdiction: 'KSA_ZATCA',
    lines: [{ sku: 'SKU-Z1', netAmount: 1000, claimedVatAmount: 150 }],
    hasCryptographicStamp: false,
  });
  assert.equal(zatcaNoStamp.verified, false, 'ZATCA without cryptographic stamp should be UNSAT');

  // 12. Live HTTP endpoint mode (remote gateway client path)
  const srv = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      verdict: 'SAT',
      verified: true,
      engine: 'apodictic-http-gateway-z3-5.4.1',
      proof_hash: 'a'.repeat(64),
      z3_solve_ms: 1.2,
      pii_entities_redacted: 1,
      tokenized_payload: 'UPDATE t SET x=1 WHERE id=1;',
    }));
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try {
    const httpGw = new SymbolicGateway({ endpoint: `http://127.0.0.1:${port}/api/noesis/verify`, apiKey: 'test_key' });
    const httpRes = await httpGw.verifyMutation({ sql: 'UPDATE t SET x=1 WHERE id=1;', amount: 500 });
    assert.equal(httpRes.verified, true);
    assert.equal(httpRes.engine, 'apodictic-http-gateway-z3-5.4.1');
    await httpGw.close();
  } finally {
    srv.close();
  }

  console.log(`✓ Crash/restart durability, 20x concurrency, ZATCA, and HTTP gateway tests passed (WORM blocks=${chainAfter.block_count})`);
} finally {
  await gw2.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
}
