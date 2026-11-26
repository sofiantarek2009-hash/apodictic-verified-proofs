import type { SymbolicGateway, VerifyMutationInput } from '../index.d.ts';

export interface VercelAdapterOptions extends Partial<VerifyMutationInput> {
  onBlock?: 'return' | 'throw';
  extractInput?: (input: unknown) => VerifyMutationInput;
}

export declare function wrapVercelAITool<T extends { execute: (...args: any[]) => Promise<any> }>(
  toolObj: T,
  gateway: SymbolicGateway,
  options?: VercelAdapterOptions
): T;

export declare function wrapVercelAITools<T extends Record<string, any>>(
  toolsRecord: T,
  gateway: SymbolicGateway,
  options?: VercelAdapterOptions
): T;
