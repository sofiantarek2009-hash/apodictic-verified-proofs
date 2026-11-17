export interface SymbolicGatewayOptions {
  posture?: 'MODE_A_AIRGAP' | 'MODE_B_HYBRID';
  vaultPath?: string;
  forbidRawLiterals?: boolean;
  endpoint?: string;
  apiKey?: string;
  repoRoot?: string;
  pythonBin?: string;
  stateDbPath?: string;
  timeoutMs?: number;
}

export interface ScrubResult {
  sanitized: string;
  redactions: number;
  symbolCount: number;
}

export interface VerifyMutationInput {
  sql: string;
  action?: string;
  accountId?: string;
  amount?: number;
  currentBalance?: number;
  minReserve?: number;
  maxAutonomousLimit?: number;
  cfoSigned?: boolean;
  statutoryVat?: number;
  expectedVat?: number;
  targetSystem?: 'postgresql' | 'odoo_v18' | 'sap_s4hana' | 'stripe';
}

export interface VerifyMutationResult {
  verdict: 'SAT' | 'UNSAT';
  verified: boolean;
  engine: string;
  proofId?: string;
  proofDigest?: string;
  blockIndex?: number;
  blockHash?: string;
  rollbackBatchId?: string | null;
  z3SolveMs?: number;
  totalLatencyMs?: number;
  redactions: number;
  sanitizedSql: string;
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
  scrubSqlAst(input: string): ScrubResult;
  rehydrate(text: string): string;
  verifyMutation(input: VerifyMutationInput): Promise<VerifyMutationResult>;
  rollback(batchId: string): Promise<Record<string, unknown>>;
  verifyThreeWayMatch(input: ThreeWayMatchInput): Promise<Record<string, unknown>>;
  verifyTaxCompliance(input: TaxComplianceInput): Promise<Record<string, unknown>>;
  bitemporalInsert(input: { entityId: string; data: Record<string, unknown>; validStart: number; validEnd?: number; systemTime?: number }): Promise<Record<string, unknown>>;
  bitemporalRestate(input: { entityId: string; data: Record<string, unknown>; validStart: number; validEnd?: number; systemTime?: number }): Promise<Record<string, unknown>>;
  bitemporalAsOf(input: { entityId: string; validTime: number; systemTime: number }): Promise<{ found: boolean; data: Record<string, unknown> | null }>;
  verifyAuditChain(): Promise<{ valid: boolean; block_count: number; tip_hash: string }>;
  health(): Promise<Record<string, unknown>>;
  close(): Promise<void>;
}

export default SymbolicGateway;
