/**
 * @apodictic/sdk/langgraph — Drop-in LangGraph Tool & Node Verification Wrapper
 */

function extractPayload(input, options = {}) {
  if (typeof options.extractInput === 'function') {
    return options.extractInput(input);
  }
  const obj = typeof input === 'string' ? { sql: input } : (input && typeof input === 'object' ? input : {});
  return {
    sql: obj.sql || obj.query || obj.payload || (typeof input === 'string' ? input : JSON.stringify(obj)),
    action: obj.action || options.action || 'TOOL_WRITE',
    accountId: obj.accountId || options.accountId || 'langgraph_agent',
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

export function wrapLangGraphTool(tool, gateway, options = {}) {
  if (!gateway || typeof gateway.verifyMutation !== 'function') {
    throw new Error('wrapLangGraphTool requires an initialized SymbolicGateway instance');
  }
  const verify = async (input) => gateway.verifyMutation(extractPayload(input, options));

  const wrappedCall = async (input, config) => {
    const verdict = await verify(input);
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
        proof_digest: verdict.proofDigest,
      });
    }
    if (typeof tool === 'function') return tool(input, config);
    if (typeof tool.invoke === 'function') return tool.invoke(input, config);
    if (typeof tool.func === 'function') return tool.func(input, config);
    throw new Error('LangGraph tool must be callable or define .invoke() / .func()');
  };

  if (typeof tool === 'function') {
    return wrappedCall;
  }

  return {
    ...tool,
    invoke: wrappedCall,
    func: wrappedCall,
  };
}

export function createApodicticLangGraphNode(gateway, toolsByName = {}, options = {}) {
  const wrapped = Object.fromEntries(
    Object.entries(toolsByName).map(([name, t]) => [name, wrapLangGraphTool(t, gateway, options)])
  );
  return async (state) => {
    const messages = Array.isArray(state?.messages) ? state.messages : [];
    const last = messages[messages.length - 1];
    const toolCalls = last?.tool_calls || state?.tool_calls || [];
    const results = [];
    for (const tc of toolCalls) {
      const target = wrapped[tc.name];
      if (!target) {
        results.push({ tool_call_id: tc.id || tc.name, name: tc.name, content: JSON.stringify({ error: `Unknown tool: ${tc.name}` }) });
        continue;
      }
      const args = typeof tc.args === 'string' ? JSON.parse(tc.args) : tc.args;
      const content = typeof target.invoke === 'function' ? await target.invoke(args) : await target(args);
      results.push({ tool_call_id: tc.id || tc.name, name: tc.name, content: typeof content === 'string' ? content : JSON.stringify(content) });
    }
    return { ...state, messages: [...messages, ...results] };
  };
}
