/**
 * @apodictic/sdk/openai — OpenAI Agents SDK Guardrail & Function Tool Wrapper
 */

function toMutationInput(rawArgs, options = {}) {
  const args = typeof rawArgs === 'string' ? JSON.parse(rawArgs) : (rawArgs || {});
  if (typeof options.extractInput === 'function') {
    return options.extractInput(args);
  }
  return {
    sql: args.sql || args.query || args.payload || JSON.stringify(args),
    action: args.action || options.action || 'OPENAI_AGENT_WRITE',
    accountId: args.accountId || options.accountId || 'openai_agent',
    amount: args.amount ?? options.amount,
    currentBalance: args.currentBalance ?? options.currentBalance ?? 250000,
    minReserve: args.minReserve ?? options.minReserve ?? 50000,
    maxAutonomousLimit: args.maxAutonomousLimit ?? options.maxAutonomousLimit ?? 50000,
    cfoSigned: Boolean(args.cfoSigned ?? options.cfoSigned),
    targetSystem: args.targetSystem || options.targetSystem || 'postgresql_wal',
    stateless: options.stateless !== false,
    odoo: args.odoo,
  };
}

export function wrapOpenAITool(toolDef, gateway, options = {}) {
  if (!gateway || typeof gateway.verifyMutation !== 'function') {
    throw new Error('wrapOpenAITool requires an initialized SymbolicGateway instance');
  }
  const origExec = typeof toolDef === 'function' ? toolDef : toolDef.execute || toolDef.run;
  if (typeof origExec !== 'function') {
    throw new Error('OpenAI tool must be a function or expose .execute() / .run()');
  }

  const guarded = async (ctxOrArgs, maybeArgs) => {
    const args = maybeArgs !== undefined ? maybeArgs : ctxOrArgs;
    const verdict = await gateway.verifyMutation(toMutationInput(args, options));
    if (!verdict.verified) {
      if (options.onBlock === 'throw') {
        const err = new Error(`APODICTIC_BLOCK: ${verdict.reason || verdict.unsatCore?.join(', ')}`);
        err.verdict = verdict;
        throw err;
      }
      return JSON.stringify({
        blocked: true,
        verdict: verdict.verdict,
        unsat_core: verdict.unsatCore,
        reason: verdict.reason,
        counterfactual_patch: verdict.counterfactualPatch,
      });
    }
    return maybeArgs !== undefined ? origExec(ctxOrArgs, maybeArgs) : origExec(args);
  };

  if (typeof toolDef === 'function') return guarded;
  return {
    ...toolDef,
    execute: guarded,
    ...(typeof toolDef.run === 'function' ? { run: guarded } : {}),
  };
}

export function createOpenAIGuardrail(gateway, options = {}) {
  if (!gateway || typeof gateway.verifyMutation !== 'function') {
    throw new Error('createOpenAIGuardrail requires an initialized SymbolicGateway instance');
  }
  return {
    name: options.name || 'apodictic_precommit_guardrail',
    execute: async ({ input }) => {
      const verdict = await gateway.verifyMutation(toMutationInput(input, options));
      return {
        tripwireTriggered: !verdict.verified,
        outputInfo: verdict,
      };
    },
  };
}
