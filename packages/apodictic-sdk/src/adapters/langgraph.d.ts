import type { SymbolicGateway, VerifyMutationInput, VerifyMutationResult } from '../index.d.ts';

export interface AdapterOptions extends Partial<VerifyMutationInput> {
  onBlock?: 'return' | 'throw';
  extractInput?: (input: unknown) => VerifyMutationInput;
}

export declare function wrapLangGraphTool<T extends Record<string, unknown> | ((...args: any[]) => any)>(
  tool: T,
  gateway: SymbolicGateway,
  options?: AdapterOptions
): T;

export declare function createApodicticLangGraphNode(
  gateway: SymbolicGateway,
  toolsByName: Record<string, unknown>,
  options?: AdapterOptions
): (state: Record<string, unknown>) => Promise<Record<string, unknown>>;
