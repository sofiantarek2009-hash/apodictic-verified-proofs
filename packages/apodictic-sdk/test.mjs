import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { SymbolicGateway } from './src/index.mjs';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'apodictic-sdk-test-'));
const stateDbPath = path.join(tmpDir, 'enclave_state.db');
const gw = new SymbolicGateway({ posture: 'MODE_B_HYBRID', forbidRawLiterals: true, stateDbPath });
let stagedBatchAfterRestart = null;

try {
  // 1. Zero-PII SQL AST scrubbing + Zero-Width character evasion defense
  const rawSql = "SELECT national_id, iban FROM claims WHERE tin = 'ETA-301099481' AND email = 'ap@nile-pharma.eg' AND iban = 'DE89370400440532013000'";
  const scrubbed = gw.scrubSqlAst(rawSql);
  assert(!scrubbed.sanitized.includes('ETA-301099481'));
  assert(!scrubbed.sanitized.includes('ap@nile-pharma.eg'));
  assert(!scrubbed.sanitized.includes('DE89370400440532013000'));
  assert.equal(gw.rehydrate(scrubbed.sanitized), rawSql);

  // 2. Real Z3 5.4.1 blocking: DROP, zero-width DROP, multi-statement SQLi, arithmetic drain, verifySql() alias
  const dropRes = await gw.verifyMutation({ sql: 'DROP TABLE account_move CASCADE;' });
  assert.equal(dropRes.verdict, 'UNSAT');
  assert.equal(dropRes.verified, false);
  assert.match(dropRes.proofDigest, /^[a-f0-9]{64}$/);

  const zwDrop = await gw.verifyMutation({ sql: 'D\u200bROP TABLE account_move;' });
  assert.equal(zwDrop.verified, false, 'Zero-width obfuscated DROP was not blocked');

  const multiStmt = await gw.verifySql('SELECT id FROM invoices WHERE id = 1; DROP TABLE account_move;');
  assert.equal(multiStmt.verified, false, 'Multi-statement SQL injection bypassed verifier');

  const arithDrain = await gw.verifySql('UPDATE accounts SET balance = balance - 90000 WHERE id = 1;', {
    currentBalance: 100000,
    minReserve: 25000,
    maxAutonomousLimit: 50000,
    cfoSigned: false,
  });
  assert.equal(arithDrain.verified, false, 'Arithmetic balance drain without explicit amount bypassed Z3');

  const safeSqlRes = await gw.verifySql('UPDATE invoices SET total = 100 WHERE id = 1;', {
    amount: 100,
    currentBalance: 250000,
    minReserve: 50000,
    maxAutonomousLimit: 50000,
  });
  assert.equal(safeSqlRes.verified, true, 'verifySql valid call failed');

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

  // 4. Staged atomic rollback + persist one batch across restart
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

  const validPersist = await gw.verifyMutation({
    sql: "UPDATE vendor_disbursements SET status='STAGED', amount=5200 WHERE id=4093;",
    accountId: 'acct_rb_persist',
    amount: 5200,
    cfoSigned: true,
  });
  assert.equal(validPersist.verified, true);
  stagedBatchAfterRestart = validPersist.rollbackBatchId;

  // 5. 3-Way Match Z3 Solver (phantom overbilling blocked)
  const matchBad = await gw.verifyThreeWayMatch({
    po: { poId: 'PO-1', sku: 'MED-1', orderedQty: 100, unitPrice: 50 },
    receipts: [{ receiptId: 'GRN-1', poId: 'PO-1', sku: 'MED-1', receivedQty: 60 }],
    invoices: [{ invoiceId: 'INV-1', poId: 'PO-1', sku: 'MED-1', billedQty: 100, billedUnitPrice: 50 }],
  });
  assert.equal(matchBad.matched, false);
  assert.equal(matchBad.verdict, 'UNSAT');

  // 6. Statutory Tax Solver (Egypt ETA 14% drift blocked)
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

  console.log(`✓ @apodictic/sdk full 8-subsystem tests passed (WORM blocks=${chain.block_count}, Z3=${h.z3_version})`);
} finally {
  await gw.close();
}

// 9. Crash & Restart Durability Test (velocity + rollback across restart)
const gw2 = new SymbolicGateway({ posture: 'MODE_B_HYBRID', forbidRawLiterals: true, stateDbPath });
try {
  const afterCrash = await gw2.verifyMutation({
    sql: 'UPDATE vendor_disbursements SET amount=45000 WHERE id=99;',
    accountId: 'smurf_acct_1',
    amount: 45000,
    maxAutonomousLimit: 50000,
    cfoSigned: false,
  });
  assert.equal(afterCrash.verified, false, 'Velocity smurfing state was lost after worker restart!');

  const rbRestart = await gw2.rollback(stagedBatchAfterRestart);
  assert.equal(rbRestart.success, true, 'Rollback batch did not survive worker restart!');

  const chainAfter = await gw2.verifyAuditChain();
  assert.equal(chainAfter.valid, true, 'WORM hash chain corrupted across restart!');

  // 10. 20 concurrent Promise.all requests on one persistent worker
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
  assert.equal(concurrent.filter((r) => r.verified).length, 20, 'Concurrent multiplexing dropped valid requests');

  // 11. ZATCA missing cryptographic stamp rejection
  const zatcaNoStamp = await gw2.verifyTaxCompliance({
    jurisdiction: 'KSA_ZATCA',
    lines: [{ sku: 'SKU-Z1', netAmount: 1000, claimedVatAmount: 150 }],
    hasCryptographicStamp: false,
  });
  assert.equal(zatcaNoStamp.verified, false);

  // 12. Remote HTTP endpoint mode: MUST scrub PII BEFORE sending HTTP request!
  let capturedBody = null;
  const srv = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      capturedBody = JSON.parse(raw);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        verdict: 'SAT',
        verified: true,
        engine: 'apodictic-http-gateway-z3-5.4.1',
        proof_hash: 'a'.repeat(64),
        z3_solve_ms: 1.2,
      }));
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  try {
    const httpGw = new SymbolicGateway({ endpoint: `http://127.0.0.1:${port}/api/apodictic/verify`, apiKey: 'test_key' });
    const httpRes = await httpGw.verifyMutation({
      sql: "UPDATE payouts SET iban='DE89370400440532013000', email='cfo@acme.io' WHERE id=1;",
      amount: 500,
    });
    assert.equal(httpRes.verified, true);
    assert.ok(!capturedBody.payload.includes('DE89370400440532013000'), 'Raw IBAN leaked over HTTP gateway!');
    assert.ok(!capturedBody.payload.includes('cfo@acme.io'), 'Raw email leaked over HTTP gateway!');
    await httpGw.close();
  } finally {
    srv.close();
  }

  // 13. Declarative Policy + Transitive 2-Hop Entity Hierarchy DAG (Z3 5.4.1)
  const scopedPolicy = `
    permit(
      principal in Group::"cfo_approvers",
      action in [Action::"UPDATE"],
      resource in Pool::"treasury_ops"
    ) when {
      context.post_balance >= context.min_reserve &&
      context.amount <= context.spending_limit
    };
  `;
  const dag = {
    'User::"alice"': ['Group::"treasury_admins"'],
    'Group::"treasury_admins"': ['Group::"cfo_approvers"'],
    'User::"bob"': ['Group::"contractors"'],
    'Account::"payout_hot"': ['Pool::"treasury_ops"'],
  };
  const aliceAllow = await gw2.evaluatePolicy({
    policyText: scopedPolicy,
    action: 'UPDATE',
    principal: 'User::"alice"',
    resource: 'Account::"payout_hot"',
    entityHierarchy: dag,
    amount: 12000,
    currentBalance: 250000,
    minReserve: 50000,
    spendingLimit: 50000,
  });
  assert.equal(aliceAllow.allowed, true);
  assert.equal(aliceAllow.verdict, 'SAT');
  assert.ok(aliceAllow.principal_ancestors.includes('Group::"cfo_approvers"'));

  const bobDeny = await gw2.evaluatePolicy({
    policyText: scopedPolicy,
    action: 'UPDATE',
    principal: 'User::"bob"',
    resource: 'Account::"payout_hot"',
    entityHierarchy: dag,
    amount: 12000,
    currentBalance: 250000,
    minReserve: 50000,
    spendingLimit: 50000,
  });
  assert.equal(bobDeny.allowed, false);
  assert.equal(bobDeny.verdict, 'UNSAT');
  assert.ok(bobDeny.unsat_core.includes('POLICY_ENTITY_HIERARCHY_MATCH'));

  // 14. 2-Phase Double-Entry Escrow Hold (debits_pending) -> Flush (debits_posted) + Conservation
  const escrowHold = await gw2.verifyMutation({
    sql: "UPDATE payouts SET amount = 18500 WHERE vendor_iban = 'DE89370400440532013000' AND id = 7;",
    accountId: 'escrow_double_entry_acct',
    amount: 18500,
    currentBalance: 250000,
    minReserve: 50000,
    targetSystem: 'stripe',
  });
  assert.equal(escrowHold.verified, true);
  assert.equal(escrowHold.escrowStatus, 'ESCROW_HELD');
  assert.equal(escrowHold.doubleEntryAccount.debits_pending, 18500);
  assert.equal(escrowHold.doubleEntryAccount.debits_posted, 0);
  assert.equal(escrowHold.doubleEntryAccount.available_balance, 231500);
  assert.equal(escrowHold.walBeforeImage.balance, 250000);

  const flushed = await gw2.flushEscrow({ batchId: escrowHold.rollbackBatchId });
  assert.equal(flushed.flushed_count, 1);
  assert.equal(flushed.dispatched[0].double_entry_account.debits_pending, 0);
  assert.equal(flushed.dispatched[0].double_entry_account.debits_posted, 18500);
  assert.equal(flushed.dispatched[0].double_entry_account.available_balance, 231500);

  // 15. RFC 6962 Binary Merkle Tree Inclusion Proof (O(log N) Audit Path)
  const merkleProof = await gw2.getMerkleInclusionProof(escrowHold.blockIndex);
  assert.equal(merkleProof.spec, 'RFC-6962-Certificate-Transparency-v1');
  assert.equal(merkleProof.inclusion_verified, true);
  assert.ok(Array.isArray(merkleProof.audit_path) && merkleProof.audit_path.length >= 1);

  // 16. ISO-7064 Mod-97-10 & Luhn Mod-10 Scrubbing + Negative Test Against Non-Luhn Digits
  const dlpSample = gw2.scrubSqlAst("PAY vendor IBAN DE89370400440532013000 card 4532015112830366 order 1234567890123456");
  assert.ok(dlpSample.sanitized.includes('<SYM_IBAN_'));
  assert.ok(dlpSample.sanitized.includes('<SYM_CARD_'));
  assert.ok(dlpSample.sanitized.includes('1234567890123456'));
  assert.equal(dlpSample.dlpChecksums.ibanMod97ValidCount >= 1, true);
  assert.equal(dlpSample.dlpChecksums.luhnPanValidCount, 1);

  // 17. Native Rust Daemon Fast-Path (engine: 'rust', zero Python, libz3 C FFI + pgoutput CDC)
  const rustGw = new SymbolicGateway({ engine: 'rust', forbidRawLiterals: true });
  try {
    const pgoutputBeginHex = '42' + '0000000001000000' + '0000000000000000' + '0000002a';
    const rustSat = await rustGw.verifyMutation({
      sql: "UPDATE vendor_disbursements SET amount = 18500 WHERE vendor_iban = 'DE89370400440532013000' AND id = 9;",
      accountId: 'rust_fastpath_1',
      amount: 18500,
      currentBalance: 250000,
      minReserve: 50000,
      maxAutonomousLimit: 50000,
      pgoutputHex: pgoutputBeginHex,
    });
    assert.equal(rustSat.verified, true);
    assert.equal(rustSat.verdict, 'SAT');
    assert.equal(rustSat.engine, 'apodictic-rust-daemon-libz3-ffi');
    assert.ok(!rustSat.sanitizedSql.includes('DE89370400440532013000'));
    assert.equal(rustSat.pgoutputDecoded?.ok, true);
    assert.equal(rustSat.pgoutputDecoded?.message?.Begin?.xid, 42);

    const rustUnsat = await rustGw.verifyMutation({
      sql: 'UPDATE vendor_disbursements SET amount = 190000 WHERE id = 10;',
      accountId: 'rust_fastpath_1',
      amount: 190000,
      currentBalance: 250000,
      minReserve: 50000,
      maxAutonomousLimit: 50000,
      cfoSigned: false,
    });
    assert.equal(rustUnsat.verified, false);
    assert.equal(rustUnsat.verdict, 'UNSAT');

    const rustDrop = await rustGw.verifyMutation({
      sql: 'DROP TABLE vendor_disbursements;',
      accountId: 'rust_fastpath_1',
    });
    assert.equal(rustDrop.verified, false);
    assert.equal(rustDrop.verdict, 'UNSAT');
  } finally {
    await rustGw.close();
  }

  // 18. PGlite WASM Shadow Postgres ("Execute-Then-Prove") + Hidden Trigger Drain & Subquery Detection
  const triggerSchema = `
    CREATE TABLE accounts (id TEXT PRIMARY KEY, balance DOUBLE PRECISION NOT NULL);
    CREATE TABLE vendor_disbursements (id INT PRIMARY KEY, account_id TEXT NOT NULL, amount DOUBLE PRECISION NOT NULL);
    CREATE OR REPLACE FUNCTION drain_hidden() RETURNS TRIGGER AS $$
    BEGIN
      UPDATE accounts SET balance = balance - 90000 WHERE id = NEW.account_id;
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    CREATE TRIGGER trg_hidden_drain
    AFTER INSERT ON vendor_disbursements
    FOR EACH ROW EXECUTE FUNCTION drain_hidden();
  `;
  const shadowTriggerDrain = await gw2.shadowExecuteAndProve({
    sql: "INSERT INTO vendor_disbursements (id, account_id, amount) VALUES (101, 'shadow_acct_1', 1000);",
    accountId: 'shadow_acct_1',
    currentBalance: 250000,
    minReserve: 50000,
    maxAutonomousLimit: 50000,
    cfoSigned: false,
    schemaSql: triggerSchema,
    seedSql: "INSERT INTO accounts (id, balance) VALUES ('shadow_acct_1', 250000);",
  });
  assert.equal(shadowTriggerDrain.verdict, 'UNSAT');
  assert.equal(shadowTriggerDrain.verified, false);
  assert.equal(shadowTriggerDrain.engine, 'apodictic-pglite-shadow-z3');
  assert.equal(shadowTriggerDrain.observedDebit, 90000, 'Hidden PL/pgSQL trigger drain must be caught by PGlite');
  assert.equal(shadowTriggerDrain.postBalances.shadow_acct_1, 160000);
  assert.equal(shadowTriggerDrain.counterfactualPatch?.solver, 'z3.Optimize');
  assert.equal(shadowTriggerDrain.counterfactualPatch?.max_safe_amount, 50000);

  const shadowCompliant = await gw2.shadowExecuteAndProve({
    sql: "UPDATE accounts SET balance = balance - 12000 WHERE id = 'shadow_acct_ok';",
    accountId: 'shadow_acct_ok',
    currentBalance: 250000,
    minReserve: 50000,
    maxAutonomousLimit: 50000,
    cfoSigned: false,
  });
  assert.equal(shadowCompliant.verdict, 'SAT');
  assert.equal(shadowCompliant.verified, true);
  assert.equal(shadowCompliant.engine, 'apodictic-pglite-shadow-z3');
  assert.equal(shadowCompliant.observedDebit, 12000);
  assert.equal(shadowCompliant.postBalances.shadow_acct_ok, 238000);
  assert.equal(shadowCompliant.counterfactualPatch, null);

  const shadowExecErr = await gw2.shadowExecuteAndProve({
    sql: 'SELECT * FROM nonexistent_shadow_table_xyz;',
    accountId: 'shadow_acct_err',
  });
  assert.equal(shadowExecErr.verified, false);
  assert.equal(shadowExecErr.verdict, 'UNSAT');
  assert.match(String(shadowExecErr.reason), /^EXECUTION_ERROR:/);

  // 19. z3.Optimize() Counterfactual Minimal Safe SQL Patch
  const cfRes = await gw2.verifyMutation({
    sql: 'UPDATE vendor_disbursements SET amount = 90000 WHERE id = 1;',
    accountId: 'cf_acct_1',
    amount: 90000,
    currentBalance: 250000,
    minReserve: 50000,
    maxAutonomousLimit: 50000,
    cfoSigned: false,
  });
  assert.equal(cfRes.verified, false);
  assert.equal(cfRes.counterfactualPatch?.solver, 'z3.Optimize');
  assert.equal(cfRes.counterfactualPatch?.max_safe_amount, 50000);
  assert.equal(cfRes.counterfactualPatch?.reduction_delta, 40000);
  assert.equal(cfRes.counterfactualPatch?.patched_sql, 'UPDATE vendor_disbursements SET amount = 50000 WHERE id = 1;');

  // 20. Non-mangling MCP response scrubber ({ scrubQuotedLiterals: false }) & Z3 Double-Entry balance proof
  const benignScrub = gw2.scrubSqlAst("Table 'orders' updated with IBAN DE89370400440532013000", {
    scrubQuotedLiterals: false,
  });
  assert.ok(benignScrub.sanitized.includes("Table 'orders' updated"), 'Benign quoted phrase was mangled');
  assert.ok(!benignScrub.sanitized.includes('DE89370400440532013000'), 'IBAN was not scrubbed');

  const deUnsat = await gw2.verifyMutation({
    sql: 'UPDATE account_move_line SET debit = 4820.00 WHERE move_id = 9412 AND id = 48201;',
    accountId: 'de_acct_1',
    amount: 320,
    debitTotal: 4820,
    creditTotal: 4500,
  });
  assert.equal(deUnsat.verified, false);
  assert.equal(deUnsat.verdict, 'UNSAT');
  assert.match(String(deUnsat.reason), /INV_DOUBLE_ENTRY_BALANCE/);

  // 21. Adversarial SQL Bypass Suite + PII Nested Rehydration + Odoo 20 Scope/Lock Guards
  const pluralInsSpoof = await gw2.verifyMutation({
    sql: "INSERT INTO vendor_disbursements (id, account_id, amount) VALUES (1, 'a', 90000);",
    accountId: 'adv_plural_ins',
    amount: 0,
    cfoSigned: false,
  });
  assert.equal(pluralInsSpoof.verified, false, 'INSERT plural table with amount:0 spoof bypassed verifier');

  const negAddDrain = await gw2.verifyMutation({
    sql: 'UPDATE accounts SET balance = balance + (-90000) WHERE id = 1;',
    accountId: 'adv_neg_add',
    amount: 0,
    cfoSigned: false,
  });
  assert.equal(negAddDrain.verified, false, 'balance + (-90000) bypassed verifier');

  const chainedSubDrain = await gw2.verifyMutation({
    sql: 'UPDATE accounts SET balance = balance - 45000 - 45000 WHERE id = 1;',
    accountId: 'adv_chain_sub',
    cfoSigned: false,
  });
  assert.equal(chainedSubDrain.verified, false, 'Chained subtraction bypassed $50k cap');

  const literalDrain = await gw2.verifyMutation({
    sql: 'UPDATE accounts SET balance = 1 WHERE id = 1;',
    accountId: 'adv_lit_drain',
    cfoSigned: false,
  });
  assert.equal(literalDrain.verified, false, 'Direct literal balance = 1 drain bypassed verifier');

  const quotedNoCrash = gw2.scrubSqlAst("UPDATE t SET status = 'PENDING' WHERE id = 1;");
  const childEcho = gw2.scrubSqlAst("Row status is 'PENDING' today", { scrubQuotedLiterals: false });
  assert.ok(childEcho.sanitized.includes('PENDING'), 'Child quoted literal response threw or mangled');

  const nestedRaw = "Pay to 'DE89 3704 0044 0532 0130 00' urgently";
  const nestedScrub = gw2.scrubSqlAst(nestedRaw);
  assert.ok(!nestedScrub.sanitized.includes('DE89 3704 0044 0532 0130 00'));
  assert.equal(gw2.rehydrate(nestedScrub.sanitized), nestedRaw, 'Nested PII inside SQL literal failed rehydrate()');

  const commitEscape = await gw2.shadowExecuteAndProve({
    sql: 'COMMIT; UPDATE accounts SET balance = balance - 90000;',
    accountId: 'shadow_commit_escape',
  });
  assert.equal(commitEscape.verified, false);
  assert.match(String(commitEscape.reason), /TRANSACTION_CONTROL_ESCAPE_BLOCKED/);

  const odoo20Blocked = await gw2.verifyMutation({
    sql: 'POST /json/2/account.move/button_draft',
    targetSystem: 'odoo_v20',
    odoo: {
      model: 'account.move',
      method: 'button_draft',
      bearerScope: 'mcp',
      moveDate: '2026-09-01',
      hardLockDate: '2026-09-30',
      inalterableHash: 'deadbeef1234',
    },
  });
  assert.equal(odoo20Blocked.verified, false);
  assert.ok(String(odoo20Blocked.reason).includes('INV_ODOO'));

  // 22. Zero-Python Z3 5.4.1 WASM Mode (pure Node.js, no Python process spawned)
  const wasmGw = new SymbolicGateway({ engine: 'wasm', pythonBin: '/nonexistent/python999', forbidRawLiterals: true });
  try {
    const wasmSat = await wasmGw.verifySql('UPDATE accounts SET balance = balance - 12500 WHERE id = 1;', {
      accountId: 'wasm_ok_1',
      currentBalance: 250000,
      minReserve: 50000,
    });
    assert.equal(wasmSat.verified, true);
    assert.equal(wasmSat.engine, 'z3-5.4.1-wasm-smt');

    const wasmDeUnsat = await wasmGw.verifyMutation({
      sql: 'UPDATE account_move_line SET debit = 4820.00 WHERE move_id = 9412 AND id = 48201;',
      accountId: 'wasm_de_1',
      debitTotal: 4820,
      creditTotal: 4500,
    });
    assert.equal(wasmDeUnsat.verified, false);
    assert.match(String(wasmDeUnsat.reason), /INV_DOUBLE_ENTRY_BALANCE/);
    assert.ok(wasmDeUnsat.counterfactualPatch?.max_safe_amount >= 0);

    const wasmAutoFallbackGw = new SymbolicGateway({ engine: 'auto', pythonBin: '/nonexistent/python999' });
    const fbRes = await wasmAutoFallbackGw.verifyMutation({ sql: 'DROP TABLE accounts;' });
    assert.equal(fbRes.verified, false);
    assert.equal(fbRes.engine, 'z3-5.4.1-wasm-smt');
    await wasmAutoFallbackGw.close();
  } finally {
    await wasmGw.close();
  }

  console.log(`✓ Crash/restart durability, rollback persistence, 20x concurrency, ZATCA, Zero-PII HTTP gateway, Policy DAG, 2-phase escrow, RFC 6962, Mod-97/Luhn, Rust daemon, PGlite shadow firewall, z3.Optimize, adversarial SQL bypasses, Odoo 20 firewall, and Zero-Python Z3 WASM tests passed`);
} finally {
  await gw2.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
}
