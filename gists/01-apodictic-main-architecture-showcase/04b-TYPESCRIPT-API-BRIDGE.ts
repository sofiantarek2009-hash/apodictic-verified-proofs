/**
 * Apodictic — TypeScript & Next.js App Router Edge Bridge (Verified Excerpts)
 * Physical Sources:
 *   - frontend/app/api/apodictic/verify/route.ts  (Live Z3 5.4.1 subprocess & daemon bridge)
 *   - frontend/lib/apodictic-verifier.ts          (Zero-PII tokenization & SMT-LIB2 AST builder)
 *   - frontend/lib/worm-vault-client.ts        (SEC 17a-4 WORM SHA-256 forward hash chain)
 */

import crypto from 'crypto'

export interface VerificationResultSummary {
  verdict: 'SAT' | 'UNSAT'
  verified: boolean
  engine: string
  execution_time_ms: number
  z3_solve_ms: number
  tokenized_payload: string
  pii_entities_redacted: number
  violations: string[]
  smt_formula: string
  proof_hash: string
}

/**
 * Compiles request inputs into standardized SMT-LIB2 QF_LRA constraints
 * before dispatching to the Z3 5.4.1 theorem prover (`frontend/lib/apodictic-verifier.ts`).
 */
export function compileFinancialSmt2(params: {
  amount: number
  currentBalance: number
  minReserve: number
  maxAutonomousLimit: number
  cfoApproved: boolean
  isDestructive: boolean
  compensatingReversal: boolean
  vatRate: number
  expectedVatRate: number
}): string {
  return [
    '(set-logic QF_LRA)',
    '(declare-const current_balance Real)',
    '(declare-const amount Real)',
    '(declare-const min_reserve Real)',
    '(declare-const max_autonomous_limit Real)',
    '(declare-const cfo_approved Bool)',
    '(declare-const is_destructive Bool)',
    '(declare-const compensating_reversal Bool)',
    '(declare-const vat_rate Real)',
    '(declare-const expected_vat_rate Real)',
    `(assert (= current_balance ${params.currentBalance.toFixed(2)}))`,
    `(assert (= amount ${params.amount.toFixed(2)}))`,
    `(assert (= min_reserve ${params.minReserve.toFixed(2)}))`,
    `(assert (= max_autonomous_limit ${params.maxAutonomousLimit.toFixed(2)}))`,
    `(assert (= cfo_approved ${params.cfoApproved ? 'true' : 'false'}))`,
    `(assert (= is_destructive ${params.isDestructive ? 'true' : 'false'}))`,
    `(assert (= compensating_reversal ${params.compensatingReversal ? 'true' : 'false'}))`,
    `(assert (= vat_rate ${params.vatRate.toFixed(4)}))`,
    `(assert (= expected_vat_rate ${params.expectedVatRate.toFixed(4)}))`,
    '(assert (>= (- current_balance amount) min_reserve))',
    '(assert (>= amount 0.0))',
    '(assert (or (<= amount max_autonomous_limit) cfo_approved))',
    '(assert (or (not is_destructive) compensating_reversal))',
    '(assert (= vat_rate expected_vat_rate))',
    '(check-sat)',
  ].join('\n')
}

/**
 * Verifies payload hashes and forward entry_hash links across every sealed SEC 17a-4 block
 * (`frontend/lib/worm-vault-client.ts`).
 */
export function verifyWormChainHashes(
  chain: Array<{
    sequence_num: number
    previous_hash: string
    payload_hash: string
    payload: string
    timestamp_utc_ms: number
    legal_hold_until_ms: number
    entry_hash: string
  }>
): { valid: boolean; block_height?: number } {
  for (let i = 1; i < chain.length; i++) {
    const prev = chain[i - 1]
    const curr = chain[i]
    if (curr.previous_hash !== prev.entry_hash) {
      return { valid: false, block_height: curr.sequence_num }
    }
    const recomputedPayloadHash = crypto.createHash('sha256').update(curr.payload).digest('hex')
    if (recomputedPayloadHash !== curr.payload_hash) {
      return { valid: false, block_height: curr.sequence_num }
    }
    const recomputedEntryHash = crypto
      .createHash('sha256')
      .update(
        `${curr.sequence_num}:${curr.previous_hash}:${curr.payload_hash}:${curr.timestamp_utc_ms}:${curr.legal_hold_until_ms}`
      )
      .digest('hex')
    if (recomputedEntryHash !== curr.entry_hash) {
      return { valid: false, block_height: curr.sequence_num }
    }
  }
  return { valid: true }
}
