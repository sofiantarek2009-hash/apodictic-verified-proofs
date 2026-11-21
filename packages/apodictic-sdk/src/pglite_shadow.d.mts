import type { SymbolicGateway, VerifyMutationInput, VerifyMutationResult } from './index.d.ts';

export interface CounterfactualPatch {
  max_safe_amount: number;
  reduction_delta: number;
  patched_sql: string | null;
  solver: string;
}

export interface ShadowExecuteInput extends VerifyMutationInput {
  schemaSql?: string;
  seedSql?: string;
}

export interface ShadowExecuteResult {
  verdict: 'SAT' | 'UNSAT';
  verified: boolean;
  engine: 'apodictic-pglite-shadow-z3';
  rowsAffected: number;
  observedDebit: number;
  observedDeltas: Record<string, { before: number; after: number; delta: number }>;
  postBalances: Record<string, number>;
  z3Proof: VerifyMutationResult;
  counterfactualPatch: CounterfactualPatch | null;
  reason?: string | null;
  executionError?: string | null;
  latencyMs: number;
}

export declare class ShadowPostgresVerifier {
  constructor(gatewayOrOptions?: SymbolicGateway | Record<string, unknown>, options?: Record<string, unknown>);
  shadowExecuteAndProve(input?: ShadowExecuteInput): Promise<ShadowExecuteResult>;
  close(): Promise<void>;
}

export default ShadowPostgresVerifier;
