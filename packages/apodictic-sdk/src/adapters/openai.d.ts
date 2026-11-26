import type { SymbolicGateway, VerifyMutationInput, VerifyMutationResult } from '../index.d.ts';

export interface OpenAIAdapterOptions extends Partial<VerifyMutationInput> {
  name?: string;
  onBlock?: 'return' | 'throw';
  extractInput?: (input: unknown) => VerifyMutationInput;
}

export declare function wrapOpenAITool<T extends Record<string, unknown> | ((...args: any[]) => any)>(
  toolDef: T,
  gateway: SymbolicGateway,
  options?: OpenAIAdapterOptions
): T;

export declare function createOpenAIGuardrail(
  gateway: SymbolicGateway,
  options?: OpenAIAdapterOptions
): {
  name: string;
  execute: (params: { input: unknown }) => Promise<{ tripwireTriggered: boolean; outputInfo: VerifyMutationResult }>;
};
