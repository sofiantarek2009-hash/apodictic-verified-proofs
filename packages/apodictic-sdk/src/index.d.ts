export interface SymbolicGatewayOptions {
  posture?: 'MODE_A_AIRGAP' | 'MODE_B_HYBRID';
  airgap?: boolean;
  vaultPath?: string;
  forbidRawLiterals?: boolean;
  endpoint?: string;
  apiKey?: string;
  repoRoot?: string;
  pythonBin?: string;
  engine?: 'python' | 'wasm' | 'rust' | 'auto';
  rustKernelPath?: string;
  stateDbPath?: string;
  timeoutMs?: number;
}

export interface ScrubResult {
  sanitized: string;
  redactions: number;
  symbolCount: number;
  dlpChecksums?: {
    ibanMod97ValidCount: number;
    luhnPanValidCount: number;
    validators: string[];
  };
}

export interface VerifyMutationInput {
  sql: string;
  action?: string;
  accountId?: string;
  amount?: number;
  debitTotal?: number;
  creditTotal?: number;
  pgoutputHex?: string;
  engine?: 'python' | 'wasm' | 'rust';
  stateless?: boolean;
  currentBalance?: number;
  minReserve?: number;
  maxAutonomousLimit?: number;
  cfoSigned?: boolean;
  approvalToken?: string;
  statutoryVat?: number;
  expectedVat?: number;
  targetSystem?: 'postgresql' | 'odoo_v18' | 'odoo_v19' | 'odoo_v20' | 'sap_s4hana' | 'stripe';
  odoo?: Record<string, unknown>;
}

export { terminateZ3WasmThreads } from './z3_wasm_verifier.mjs';

export interface VerifyMutationResult {
  verdict: 'SAT' | 'UNSAT';
  verified: boolean;
  engine: string;
  proofId?: string;
  proofDigest?: string;
  blockIndex?: number;
  blockHash?: string;
  rollbackBatchId?: string | null;
  escrowStatus?: string | null;
  doubleEntryAccount?: Record<string, unknown> | null;
  walBeforeImage?: Record<string, unknown> | null;
  rfc6962LeafHash?: string | null;
  rfc6962TreeRoot?: string | null;
  dlpChecksums?: Record<string, unknown> | null;
  odoo20Evaluation?: Record<string, unknown>;
  z3SolveMs?: number;
  totalLatencyMs?: number;
  redactions: number;
  sanitizedSql: string;
  counterfactualPatch?: {
    max_safe_amount: number;
    reduction_delta: number;
    patched_sql: string | null;
    solver: string;
  } | null;
  reason?: string | null;
}

export interface ThreeWayMatchInput {
  po: { poId: string; sku: string; orderedQty: number; unitPrice: number };
  receipts: Array<{ receiptId: string; poId: string; sku: string; receivedQty: number }>;
  invoices: Array<{ invoiceId: string; poId: string; sku: string; billedQty: number; billedUnitPrice: number }>;
  priceTolerancePct?: number;
}

export interface TaxComplianceInput {
  jurisdiction: 'KSA_ZATCA' | 'EGYPT_ETA' | 'EU_VAT_DE' | 'EU_REVERSE_CHARGE';
  lines: Array<{
    sku: string;
    netAmount: number;
    claimedVatAmount: number;
    claimedWhtAmount?: number;
    isExempt?: boolean;
  }>;
  hasCryptographicStamp?: boolean;
  tolerance?: number;
}

export declare class SymbolicGateway {
  constructor(options?: SymbolicGatewayOptions);
  scrubSqlAst(input: string, opts?: { scrubQuotedLiterals?: boolean }): ScrubResult;
  rehydrate(text: string): string;
  verifyMutation(input: VerifyMutationInput): Promise<VerifyMutationResult>;
  verifyMutationNativeRust(input: VerifyMutationInput): Promise<VerifyMutationResult>;
  shadowExecuteAndProve(input?: VerifyMutationInput & { schemaSql?: string; seedSql?: string }): Promise<{
    verdict: 'SAT' | 'UNSAT';
    verified: boolean;
    engine: 'apodictic-pglite-shadow-z3';
    rowsAffected: number;
    observedDebit: number;
    observedDeltas: Record<string, { before: number; after: number; delta: number }>;
    postBalances: Record<string, number>;
    z3Proof: VerifyMutationResult;
    counterfactualPatch: VerifyMutationResult['counterfactualPatch'];
    reason?: string | null;
    executionError?: string | null;
    latencyMs: number;
  }>;
  verifySql(sql: string, options?: Omit<VerifyMutationInput, 'sql'>): Promise<VerifyMutationResult>;
  rollback(batchId: string): Promise<Record<string, unknown>>;
  verifyThreeWayMatch(input: ThreeWayMatchInput): Promise<Record<string, unknown>>;
  verifyTaxCompliance(input: TaxComplianceInput): Promise<Record<string, unknown>>;
  bitemporalInsert(input: { entityId: string; data: Record<string, unknown>; validStart: number; validEnd?: number; systemTime?: number }): Promise<Record<string, unknown>>;
  bitemporalRestate(input: { entityId: string; data: Record<string, unknown>; validStart: number; validEnd?: number; systemTime?: number }): Promise<Record<string, unknown>>;
  bitemporalAsOf(input: { entityId: string; validTime: number; systemTime: number }): Promise<{ found: boolean; data: Record<string, unknown> | null }>;
  verifyAuditChain(): Promise<{ valid: boolean; block_count: number; tip_hash: string }>;
  flushEscrow(options?: { batchId?: string; coolingWindowSec?: number }): Promise<Record<string, unknown>>;
  evaluatePolicy(options?: {
    policyText?: string;
    action?: string;
    principal?: string;
    resource?: string;
    entityHierarchy?: Record<string, string[]>;
    context?: Record<string, unknown>;
    amount?: number;
    currentBalance?: number;
    minReserve?: number;
    spendingLimit?: number;
    cfoSigned?: boolean;
    reversalArmed?: boolean;
  }): Promise<Record<string, unknown>>;
  getMerkleInclusionProof(blockIndex?: number): Promise<{
    spec: string;
    block_index: number;
    leaf_index: number;
    tree_size: number;
    leaf_hash: string | null;
    root_hash: string;
    audit_path: string[];
    inclusion_verified: boolean;
  }>;
  health(): Promise<Record<string, unknown>>;
  close(): Promise<void>;
}

export { PGlite } from '@electric-sql/pglite';
export { ShadowPostgresVerifier } from './pglite_shadow.mjs';
export { Z3WasmEnclaveSession } from './z3_wasm_verifier.mjs';
export { evaluateOdoo20Call, extractOdoo20Call } from './odoo20_guard.mjs';
export {
  compileDiscoveredPolicyIr,
  discoverSchemaFromOdoo,
  discoverSchemaFromPgDsn,
  discoverSchemaFromSql,
} from './schema_discovery.mjs';
export default SymbolicGateway;
