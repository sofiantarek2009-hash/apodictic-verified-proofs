export interface DiscoveredColumn {
  name: string;
  type: string;
}

export interface DiscoveredTable {
  name: string;
  odooModel?: string;
  columns: DiscoveredColumn[];
  cascades: Array<{ table: string; references: string; rule?: string; definition?: string }>;
  isFinancial: boolean;
  isInventory: boolean;
  isProtectedTax: boolean;
  isOdooCore: boolean;
}

export interface DiscoveredTrigger {
  name: string;
  timing: string;
  events: string;
  table: string;
}

export interface SchemaDiscoveryResult {
  source: string;
  schema?: string;
  odooUrl?: string;
  tables: DiscoveredTable[];
  triggers: DiscoveredTrigger[];
  cascades: Array<{ table: string; column?: string; references: string; rule: string }>;
  savepointRecommended: boolean;
}

export interface CompiledDiscoveredPolicyResult {
  policy_ir: {
    version: '1.0';
    name: string;
    recommendedMode: 'OBSERVE';
    savepointModeRecommended: boolean;
    discoveredFrom: string;
    detectedTables: Array<{
      name: string;
      columns: string[];
      isFinancial: boolean;
      isInventory: boolean;
      isProtectedTax: boolean;
    }>;
    clauses: Array<Record<string, unknown>>;
    warnings: Array<{ severity: string; kind: string; target: string; detail: string }>;
    deadlock_check: {
      consistent: boolean;
      status: 'SAT' | 'DEADLOCK_UNSAT';
      unsat_core: string[];
      witness_example: Record<string, number> | null;
      solve_ms: number;
    };
    launch_commands: {
      postgres_observe: string;
      postgres_enforce: string;
      odoo_observe: string;
    };
  };
  deadlock_check: {
    consistent: boolean;
    status: 'SAT' | 'DEADLOCK_UNSAT';
    unsat_core: string[];
    witness_example: Record<string, number> | null;
    solve_ms: number;
  };
  financial_tables: string[];
  inventory_tables: string[];
  warnings: Array<{ severity: string; kind: string; target: string; detail: string }>;
  savepoint_recommended: boolean;
}

export declare function discoverSchemaFromSql(ddlSql: string, options?: { source?: string }): SchemaDiscoveryResult;
export declare function discoverSchemaFromPgDsn(dsn: string, options?: { schema?: string }): Promise<SchemaDiscoveryResult>;
export declare function discoverSchemaFromOdoo(
  odooUrl: string,
  options?: { models?: string[]; token?: string; db?: string }
): Promise<SchemaDiscoveryResult>;
export declare function compileDiscoveredPolicyIr(
  discovery: SchemaDiscoveryResult,
  options?: {
    name?: string;
    spendCapUsd?: number;
    minReserveUsd?: number;
    maxDiscountPct?: number;
    maxBranches?: number;
  }
): Promise<CompiledDiscoveredPolicyResult>;
