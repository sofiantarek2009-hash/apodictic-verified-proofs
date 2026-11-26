/**
 * @apodictic/sdk/vercel-ai — Vercel AI SDK `tool({ execute })` Formal Guard Wrapper
 */

function toPayload(args, options = {}) {
  if (typeof options.extractInput === 'function') {
    return options.extractInput(args);
  }
  const obj = args && typeof args === 'object' ? args : { sql: String(args || '') };
  return {
    sql: obj.sql || obj.query || obj.payload || JSON.stringify(obj),
    action: obj.action || options.action || 'VERCEL_AI_TOOL',
    accountId: obj.accountId || options.accountId || 'vercel_ai_agent',
    amount: obj.amount ?? options.amount,
    currentBalance: obj.currentBalance ?? options.currentBalance ?? 250000,
    minReserve: obj.minReserve ?? options.minReserve ?? 50000,
    maxAutonomousLimit: obj.maxAutonomousLimit ?? options.maxAutonomousLimit ?? 50000,
    cfoSigned: Boolean(obj.cfoSigned ?? options.cfoSigned),
    targetSystem: obj.targetSystem || options.targetSystem || 'postgresql_wal',
    stateless: options.stateless !== false,
    odoo: obj.odoo,
  };
}

export function wrapVercelAITool(toolObj, gateway, options = {}) {
  if (!gateway || typeof gateway.verifyMutation !== 'function') {
    throw new Error('wrapVercelAITool requires an initialized SymbolicGateway instance');
  }
  if (!toolObj || typeof toolObj.execute !== 'function') {
    throw new Error('wrapVercelAITool expects a Vercel AI tool definition with an .execute() method');
  }
  return {
    ...toolObj,
    execute: async (args, ctx) => {
      const verdict = await gateway.verifyMutation(toPayload(args, options));
      if (!verdict.verified) {
        if (options.onBlock === 'throw') {
          const err = new Error(`APODICTIC_BLOCK: ${verdict.reason || verdict.unsatCore?.join(', ')}`);
          err.verdict = verdict;
          throw err;
        }
        return {
          blocked: true,
          verdict: verdict.verdict,
          unsatCore: verdict.unsatCore,
          reason: verdict.reason,
          counterfactualPatch: verdict.counterfactualPatch,
          proofDigest: verdict.proofDigest,
        };
      }
      return toolObj.execute(args, ctx);
    },
  };
}

export function wrapVercelAITools(toolsRecord = {}, gateway, options = {}) {
  const out = {};
  for (const [key, toolObj] of Object.entries(toolsRecord)) {
    out[key] = toolObj && typeof toolObj.execute === 'function' ? wrapVercelAITool(toolObj, gateway, options) : toolObj;
  }
  return out;
}
