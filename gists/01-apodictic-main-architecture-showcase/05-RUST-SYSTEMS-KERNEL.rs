use std::collections::HashMap;
use std::env;
use std::io::{self, BufRead, Write};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use apodictic_cdc_engine::PgOutputParser;
use apodictic_merkle_trie::HexaryMerkleTrie;
use apodictic_policy_engine::{evaluate_cedar, evaluate_cel, evaluate_rego, PolicyEvalResult};
use apodictic_sovereign_audit_vault::SovereignAuditVault;
use apodictic_symbolic_sql::{
    compile_sql_to_qf_auflia_smt2, parse_sql_ast, CompiledSqlAst, SmtArrayOp,
};
use apodictic_z3_engine::{
    DualSolverProof, LibZ3FfiEngine, NativeZ3FfiProof, OxizDualVerifier,
};
use apodictic_zero_leak_sanitizer::ZeroLeakSanitizer;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct CedarEvalRequest {
    policy_src: String,
    #[serde(default)]
    entities_json: Option<String>,
    principal: String,
    action: String,
    resource: String,
    #[serde(default)]
    context_json: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegoEvalRequest {
    #[serde(alias = "policy")]
    rego_src: String,
    #[serde(default, alias = "data")]
    data_json: Option<serde_json::Value>,
    #[serde(default, alias = "input")]
    input_json: Option<serde_json::Value>,
    #[serde(default)]
    query_rule: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CelEvalRequest {
    #[serde(alias = "expression")]
    expr_src: String,
    #[serde(default, alias = "context", alias = "vars")]
    vars_json: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
struct KernelPolicyEvalReceipt {
    allowed: bool,
    engine: String,
    reason: String,
    reasons: Vec<String>,
    output_json: Option<serde_json::Value>,
}

impl From<PolicyEvalResult> for KernelPolicyEvalReceipt {
    fn from(res: PolicyEvalResult) -> Self {
        let reason = if res.reasons.is_empty() {
            if res.allowed {
                format!("{}_allow", res.engine)
            } else {
                format!("{}_deny", res.engine)
            }
        } else {
            res.reasons.join("; ")
        };
        Self {
            allowed: res.allowed,
            engine: res.engine,
            reason,
            reasons: res.reasons,
            output_json: res.output_json,
        }
    }
}

fn json_value_to_raw_string(val: Option<&serde_json::Value>, default_str: &str) -> String {
    match val {
        None | Some(serde_json::Value::Null) => default_str.to_string(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => serde_json::to_string(other).unwrap_or_else(|_| default_str.to_string()),
    }
}

fn infer_rego_query_rule(rego_src: &str, explicit_rule: Option<&str>) -> String {
    if let Some(rule) = explicit_rule {
        let trimmed = rule.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    for line in rego_src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("package") {
            if rest.starts_with(char::is_whitespace) {
                if let Some(pkg) = rest.split_whitespace().next() {
                    let clean_pkg = pkg.trim_end_matches(';');
                    if !clean_pkg.is_empty() {
                        return format!("data.{}.allow", clean_pkg);
                    }
                }
            }
        }
    }
    "data.apodictic.allow".to_string()
}

#[derive(Debug, Default, Deserialize)]
struct KernelRequest {
    sql: Option<String>,
    account: Option<String>,
    amount: Option<f64>,
    current_balance: Option<f64>,
    min_reserve: Option<f64>,
    spending_limit: Option<f64>,
    cfo_signed: Option<bool>,
    pgoutput_hex: Option<String>,
    fpe_mode: Option<bool>,
    fpe_tweak: Option<String>,
    dual_solver_oxiz: Option<bool>,
    cedar_eval: Option<CedarEvalRequest>,
    rego_eval: Option<RegoEvalRequest>,
    cel_eval: Option<CelEvalRequest>,
}

#[derive(Debug, Serialize)]
struct KernelReceipt {
    kernel: &'static str,
    rustc_arch: &'static str,
    daemon_mode: bool,
    rust_sql_ast: CompiledSqlAst,
    sanitized_sql: String,
    pseudonym_map: HashMap<String, String>,
    smtlib2_qf_auflia: String,
    smt_array_store: String,
    libz3_c_ffi_proof: Option<NativeZ3FfiProof>,
    oxiz_dual_proof: Option<DualSolverProof>,
    policy_eval: Option<PolicyEvalResult>,
    rego_eval: Option<KernelPolicyEvalReceipt>,
    cel_eval: Option<KernelPolicyEvalReceipt>,
    pgoutput_decoded: Option<serde_json::Value>,
    merkle_state_root: String,
    merkle_inclusion_verified: bool,
    rfc6962_leaf_hash: Option<String>,
    rfc6962_audit_path: Vec<String>,
    worm_sequence_num: u64,
    worm_chain_integrity_verified: bool,
    timings_us: HashMap<&'static str, u128>,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex_str: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("Odd hex length".to_string());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
            .map_err(|e| format!("Invalid hex byte: {}", e))?;
        out.push(byte);
    }
    Ok(out)
}

fn build_sanitizer_from_env() -> ZeroLeakSanitizer {
    if let Ok(hex_key) = env::var("APODICTIC_DLP_KEY_HEX") {
        if let Ok(bytes) = hex_decode(&hex_key) {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return ZeroLeakSanitizer::new(key);
            }
        }
    }
    ZeroLeakSanitizer::with_random_key()
}

fn safe_f64_to_i64(val: f64, fallback: i64) -> i64 {
    if val.is_finite() {
        val.round() as i64
    } else {
        fallback
    }
}

fn execute_kernel_request(
    req: KernelRequest,
    z3_engine: Option<&Arc<LibZ3FfiEngine>>,
    vault: &mut SovereignAuditVault,
    daemon_mode: bool,
) -> KernelReceipt {
    let t_total = Instant::now();

    let raw_sql = req.sql.unwrap_or_else(|| {
        "UPDATE vendor_disbursements SET amount = 18500 WHERE vendor_iban = 'DE89370400440532013000' AND tax_id = 'ETA-402918274';".to_string()
    });
    let account = req.account.unwrap_or_else(|| "ACC_TREASURY_01".to_string());
    let current_balance = safe_f64_to_i64(req.current_balance.unwrap_or(250000.0), 0);
    let min_reserve = safe_f64_to_i64(req.min_reserve.unwrap_or(50000.0), 50000);
    let spending_limit = safe_f64_to_i64(req.spending_limit.unwrap_or(50000.0), 0);
    let cfo_signed = req.cfo_signed.unwrap_or(false);

    // 1. Pure-Rust PostgreSQL SQL AST Compiler
    let t_ast = Instant::now();
    let mut rust_sql_ast = parse_sql_ast(&raw_sql);
    let invalid_amount = req.amount.map(|a| !a.is_finite() || a < 0.0).unwrap_or(false);
    if invalid_amount {
        rust_sql_ast.is_unbounded = true;
    }
    let explicit_amt = safe_f64_to_i64(req.amount.unwrap_or(0.0), i64::MAX / 4);
    if explicit_amt > rust_sql_ast.total_debit_amount {
        rust_sql_ast.total_debit_amount = explicit_amt;
    }
    let effective_amount = if rust_sql_ast.sets_balance_zero && rust_sql_ast.total_debit_amount == 0
    {
        current_balance.max(0)
    } else {
        rust_sql_ast.total_debit_amount.max(0)
    };
    let ast_us = t_ast.elapsed().as_micros();

    // 2. ZeroLeakSanitizer (CSPRNG or APODICTIC_DLP_KEY_HEX + optional NIST SP 800-38G AES-256-FF1 FPE)
    let t_dlp = Instant::now();
    let mut sanitizer = build_sanitizer_from_env();
    let (sanitized_sql, pseudonym_map) = if req.fpe_mode == Some(true) {
        let tweak = req
            .fpe_tweak
            .as_deref()
            .unwrap_or("apodictic_fpe_enclave_v1");
        sanitizer.auto_sanitize_payload_fpe(&raw_sql, tweak.as_bytes())
    } else {
        sanitizer.auto_sanitize_payload(&raw_sql)
    };
    let dlp_us = t_dlp.elapsed().as_micros();

    // 3. Dynamic SQL-to-QF_AUFLIA SMT-LIB2 Compilation + In-Process libz3.dylib C FFI + Optional OxiZ Dual Consensus
    let t_smt = Instant::now();
    let smtlib2 = compile_sql_to_qf_auflia_smt2(
        &rust_sql_ast,
        current_balance,
        min_reserve,
        spending_limit,
        cfo_signed,
    );
    let array_op = SmtArrayOp::Store {
        array: "balances_0".to_string(),
        index: "1".to_string(),
        value: format!("{}", current_balance - effective_amount),
    };
    let smt_array_store = array_op.to_smtlib2();
    let smt_us = t_smt.elapsed().as_micros();

    let libz3_c_ffi_proof = z3_engine.map(|eng| eng.verify_smtlib2(&smtlib2));
    let z3_ffi_us = libz3_c_ffi_proof.as_ref().map(|p| p.solve_us).unwrap_or(0);

    let oxiz_dual_proof = if req.dual_solver_oxiz == Some(true) {
        let verifier = OxizDualVerifier::new(z3_engine.cloned());
        let is_destructive = rust_sql_ast.has_multi_statement
            || rust_sql_ast.is_unbounded
            || rust_sql_ast.statement_type.is_ddl_or_delete();
        let reversal_armed = !is_destructive;
        Some(verifier.verify_transaction(
            &smtlib2,
            current_balance,
            effective_amount,
            min_reserve,
            spending_limit,
            cfo_signed,
            is_destructive,
            reversal_armed,
        ))
    } else {
        None
    };

    // 3b. Optional Multi-Language Policy Engine Evaluation (Cedar / Rego / CEL)
    let cedar_raw = req.cedar_eval.map(|cedar| {
        evaluate_cedar(
            &cedar.policy_src,
            cedar.entities_json.as_deref().unwrap_or("[]"),
            &cedar.principal,
            &cedar.action,
            &cedar.resource,
            cedar.context_json.as_deref().unwrap_or("{}"),
        )
    });
    let rego_raw = req.rego_eval.map(|rego| {
        let data_str = rego
            .data_json
            .as_ref()
            .filter(|v| !v.is_null())
            .map(|v| json_value_to_raw_string(Some(v), "{}"));
        let input_str = json_value_to_raw_string(rego.input_json.as_ref(), "{}");
        let query_rule = infer_rego_query_rule(&rego.rego_src, rego.query_rule.as_deref());
        evaluate_rego(&rego.rego_src, data_str.as_deref(), &input_str, &query_rule)
    });
    let cel_raw = req.cel_eval.map(|cel| {
        let vars_str = json_value_to_raw_string(cel.vars_json.as_ref(), "{}");
        evaluate_cel(&cel.expr_src, &vars_str)
    });

    let policy_vetoed = cedar_raw.as_ref().map(|p| !p.allowed).unwrap_or(false)
        || rego_raw.as_ref().map(|p| !p.allowed).unwrap_or(false)
        || cel_raw.as_ref().map(|p| !p.allowed).unwrap_or(false);

    let mut libz3_c_ffi_proof = libz3_c_ffi_proof;
    if policy_vetoed {
        if let Some(ref mut p) = libz3_c_ffi_proof {
            p.verdict = "UNSAT".to_string();
            p.verified = false;
            if !p.unsat_core_raw.contains("INV_POLICY_DENIED") {
                p.unsat_core_raw = if p.unsat_core_raw.trim().is_empty() {
                    "(INV_POLICY_DENIED)".to_string()
                } else {
                    format!("(INV_POLICY_DENIED {})", p.unsat_core_raw.trim())
                };
            }
        }
    }
    let mut oxiz_dual_proof = oxiz_dual_proof;
    if policy_vetoed {
        if let Some(ref mut ox) = oxiz_dual_proof {
            ox.z3_verdict = "UNSAT".to_string();
            ox.oxiz_verdict = "UNSAT".to_string();
            ox.verified = false;
            if !ox.unsat_core_raw.contains("INV_POLICY_DENIED") {
                ox.unsat_core_raw = if ox.unsat_core_raw.trim().is_empty() {
                    "(INV_POLICY_DENIED)".to_string()
                } else {
                    format!("(INV_POLICY_DENIED {})", ox.unsat_core_raw.trim())
                };
            }
        }
    }

    let policy_eval = cedar_raw
        .clone()
        .or_else(|| rego_raw.clone())
        .or_else(|| cel_raw.clone());
    let rego_eval = rego_raw.map(KernelPolicyEvalReceipt::from);
    let cel_eval = cel_raw.map(KernelPolicyEvalReceipt::from);

    // 4. Optional Binary pgoutput WAL Logical Replication Decode (apodictic-cdc-engine)
    let t_cdc = Instant::now();
    let pgoutput_decoded = req.pgoutput_hex.as_deref().map(|hex_str| {
        match hex_decode(hex_str).and_then(|bytes| {
            PgOutputParser::parse_message(&bytes).map_err(|e| format!("{}", e))
        }) {
            Ok(msg) => serde_json::json!({ "ok": true, "message": msg }),
            Err(err) => serde_json::json!({ "ok": false, "error": err }),
        }
    });
    let cdc_us = t_cdc.elapsed().as_micros();

    // 5. RFC 6962 Domain-Separated Binary Merkle Tree Commitment
    let t_trie = Instant::now();
    let mut trie = HexaryMerkleTrie::new();
    trie.insert(&account, &format!("{}", current_balance - effective_amount));
    trie.insert("MIN_RESERVE_FLOOR", &format!("{}", min_reserve));
    let proof = trie.prove(&account);
    let merkle_root_hex = hex_encode(&trie.root());
    let trie_us = t_trie.elapsed().as_micros();

    // 6. Sovereign Cryptographic WORM Audit Vault (SEC 17a-4)
    let t_vault = Instant::now();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1_730_000_000_000);
    let mut meta = HashMap::new();
    meta.insert("account".to_string(), account);
    meta.insert("merkle_root".to_string(), merkle_root_hex.clone());
    meta.insert(
        "sql_op".to_string(),
        rust_sql_ast.statement_type.as_str().to_string(),
    );
    let seq = vault
        .append(sanitized_sql.as_bytes(), meta, now_ms)
        .unwrap_or(1);
    let worm_ok = vault.verify_integrity().unwrap_or(false);
    let vault_us = t_vault.elapsed().as_micros();

    let total_us = t_total.elapsed().as_micros();
    let mut timings_us = HashMap::new();
    timings_us.insert("rust_sql_ast_us", ast_us);
    timings_us.insert("zero_leak_sanitizer_us", dlp_us);
    timings_us.insert("qf_auflia_smt_emitter_us", smt_us);
    timings_us.insert("libz3_c_ffi_solve_us", z3_ffi_us);
    timings_us.insert("pgoutput_cdc_decode_us", cdc_us);
    timings_us.insert("hexary_merkle_trie_us", trie_us);
    timings_us.insert("sovereign_worm_vault_us", vault_us);
    timings_us.insert("total_rust_kernel_us", total_us);

    KernelReceipt {
        kernel: "apodictic-rust-systems-kernel-v0.2.0",
        rustc_arch: env::consts::ARCH,
        daemon_mode,
        rust_sql_ast,
        sanitized_sql,
        pseudonym_map,
        smtlib2_qf_auflia: smtlib2,
        smt_array_store,
        libz3_c_ffi_proof,
        oxiz_dual_proof,
        policy_eval,
        rego_eval,
        cel_eval,
        pgoutput_decoded,
        merkle_state_root: merkle_root_hex,
        merkle_inclusion_verified: proof.exists,
        rfc6962_leaf_hash: proof.rfc6962_leaf_hash,
        rfc6962_audit_path: proof.rfc6962_audit_path,
        worm_sequence_num: seq,
        worm_chain_integrity_verified: worm_ok,
        timings_us,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let is_daemon = args.iter().any(|a| a == "--daemon");

    let z3_engine = LibZ3FfiEngine::try_load().map(Arc::new);
    let mut vault = SovereignAuditVault::new(86400 * 1000 * 365 * 7);

    if is_daemon {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut out = io::BufWriter::new(stdout.lock());
        for line_res in stdin.lock().lines() {
            let Ok(line) = line_res else {
                break;
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let id_opt = val.get("id").cloned();
                let params_val = val.get("params").cloned().unwrap_or(val);
                let response_val = match serde_json::from_value::<KernelRequest>(params_val) {
                    Ok(req) => {
                        let receipt =
                            execute_kernel_request(req, z3_engine.as_ref(), &mut vault, true);
                        match id_opt {
                            Some(id) => serde_json::json!({ "id": id, "result": receipt }),
                            None => serde_json::to_value(&receipt).unwrap_or_default(),
                        }
                    }
                    Err(e) => match id_opt {
                        Some(id) => serde_json::json!({
                            "id": id,
                            "error": format!("Invalid KernelRequest: {}", e)
                        }),
                        None => serde_json::json!({
                            "error": format!("Invalid KernelRequest: {}", e)
                        }),
                    },
                };
                if serde_json::to_writer(&mut out, &response_val).is_ok() {
                    let _ = writeln!(out);
                    let _ = out.flush();
                }
            } else {
                let err_val = serde_json::json!({ "error": "Invalid JSON request" });
                let _ = serde_json::to_writer(&mut out, &err_val);
                let _ = writeln!(out);
                let _ = out.flush();
            }
        }
        return;
    }

    let arg_json = args.get(1).cloned().unwrap_or_else(|| "{}".to_string());
    let req: KernelRequest = serde_json::from_str(&arg_json).unwrap_or_else(|e| {
        eprintln!("Invalid KernelRequest JSON: {}", e);
        std::process::exit(2);
    });
    let receipt = execute_kernel_request(req, z3_engine.as_ref(), &mut vault, false);
    println!("{}", serde_json::to_string(&receipt).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opa_route_rego_and_cel_schema_compat() {
        let payload = serde_json::json!({
            "rego_eval": {
                "policy": "package apodictic.treasury\nimport rego.v1\ndefault allow := false\nallow if { input.amount <= input.spending_limit }",
                "input": { "amount": 12000, "spending_limit": 50000, "action": "UPDATE" }
            },
            "cel_eval": {
                "expression": "(current_balance - amount) >= min_reserve && amount <= spending_limit",
                "context": {
                    "current_balance": 250000,
                    "amount": 12000,
                    "min_reserve": 50000,
                    "spending_limit": 50000,
                    "principal": null
                }
            }
        });
        let req: KernelRequest = serde_json::from_value(payload).unwrap();
        let mut vault = SovereignAuditVault::new(86400 * 1000);
        let receipt = execute_kernel_request(req, None, &mut vault, true);

        let rego = receipt.rego_eval.expect("rego_eval must be populated");
        assert!(rego.allowed);
        assert_eq!(rego.engine, "rego");
        assert!(!rego.reason.is_empty());

        let cel = receipt.cel_eval.expect("cel_eval must be populated");
        assert!(cel.allowed);
        assert_eq!(cel.engine, "cel");
        assert!(!cel.reason.is_empty());
    }

    #[test]
    fn test_opa_route_invalid_rego_and_cel_fail_closed() {
        let payload = serde_json::json!({
            "rego_eval": {
                "policy": "package apodictic\nallow if {{{ invalid syntax",
                "input": { "amount": 100 }
            },
            "cel_eval": {
                "expression": "amount <= &&& broken",
                "context": { "amount": 100 }
            }
        });
        let req: KernelRequest = serde_json::from_value(payload).unwrap();
        let mut vault = SovereignAuditVault::new(86400 * 1000);
        let receipt = execute_kernel_request(req, None, &mut vault, true);

        let rego = receipt.rego_eval.expect("rego_eval must be populated");
        assert!(!rego.allowed);
        assert!(rego.reason.contains("REGO_POLICY_PARSE_ERROR"));

        let cel = receipt.cel_eval.expect("cel_eval must be populated");
        assert!(!cel.allowed);
        assert!(cel.reason.contains("CEL_COMPILE_ERROR"));
    }

    #[test]
    fn test_execute_kernel_request_fpe_and_oxiz_dual_solver() {
        let req = KernelRequest {
            sql: Some(
                "UPDATE vendor_disbursements SET amount = 18500 WHERE vendor_iban = 'DE89370400440532013000';".to_string(),
            ),
            current_balance: Some(250_000.0),
            min_reserve: Some(50_000.0),
            spending_limit: Some(50_000.0),
            cfo_signed: Some(false),
            fpe_mode: Some(true),
            fpe_tweak: Some("tweak_01".to_string()),
            dual_solver_oxiz: Some(true),
            ..Default::default()
        };
        let z3 = LibZ3FfiEngine::try_load().map(Arc::new);
        let mut vault = SovereignAuditVault::new(86_400_000);
        let receipt = execute_kernel_request(req, z3.as_ref(), &mut vault, false);

        assert!(!receipt.sanitized_sql.contains("DE89370400440532013000"));
        assert!(receipt.sanitized_sql.contains("DE89"));
        assert!(receipt.merkle_inclusion_verified);
        assert!(receipt.worm_chain_integrity_verified);
        assert_eq!(receipt.worm_sequence_num, 1);

        let z3_proof = receipt.libz3_c_ffi_proof.unwrap();
        assert!(z3_proof.verified);
        let dual = receipt.oxiz_dual_proof.unwrap();
        assert!(dual.consensus_agreed);
        assert!(dual.verified);
    }

    #[test]
    fn test_execute_kernel_request_cedar_eval() {
        let payload = serde_json::json!({
            "cedar_eval": {
                "policy_src": "permit(principal == User::\"alice\", action == Action::\"pay\", resource); forbid(principal == User::\"alice\", action == Action::\"pay\", resource == Account::\"frozen\");",
                "principal": "User::\"alice\"",
                "action": "Action::\"pay\"",
                "resource": "Account::\"frozen\""
            }
        });
        let req: KernelRequest = serde_json::from_value(payload).unwrap();
        let z3_engine = LibZ3FfiEngine::try_load().map(Arc::new);
        let mut vault = SovereignAuditVault::new(86_400_000);
        let receipt = execute_kernel_request(req, z3_engine.as_ref(), &mut vault, true);
        let pe = receipt.policy_eval.unwrap();
        assert_eq!(pe.engine, "cedar");
        assert!(!pe.allowed);
        if let Some(p) = receipt.libz3_c_ffi_proof {
            assert_eq!(p.verdict, "UNSAT");
            assert!(!p.verified);
            assert!(p.unsat_core_raw.contains("INV_POLICY_DENIED"));
        }
        if let Some(ox) = receipt.oxiz_dual_proof {
            assert_eq!(ox.z3_verdict, "UNSAT");
            assert_eq!(ox.oxiz_verdict, "UNSAT");
            assert!(!ox.verified);
            assert!(ox.unsat_core_raw.contains("INV_POLICY_DENIED"));
        }
    }

    #[test]
    fn test_execute_kernel_request_pgoutput_hex_valid_and_truncated() {
        // Begin message: 'B' (42) + 8B LSN + 8B ts + 4B xid
        let mut begin = vec![b'B'];
        begin.extend_from_slice(&0x100u64.to_be_bytes());
        begin.extend_from_slice(&5000i64.to_be_bytes());
        begin.extend_from_slice(&77u32.to_be_bytes());

        let req_ok = KernelRequest {
            pgoutput_hex: Some(hex_encode(&begin)),
            ..Default::default()
        };
        let mut vault = SovereignAuditVault::new(86_400_000);
        let r_ok = execute_kernel_request(req_ok, None, &mut vault, false);
        let dec_ok = r_ok.pgoutput_decoded.unwrap();
        assert_eq!(dec_ok["ok"], serde_json::json!(true));

        let req_bad = KernelRequest {
            pgoutput_hex: Some("420001".to_string()),
            ..Default::default()
        };
        let r_bad = execute_kernel_request(req_bad, None, &mut vault, false);
        let dec_bad = r_bad.pgoutput_decoded.unwrap();
        assert_eq!(dec_bad["ok"], serde_json::json!(false));
    }

    #[test]
    fn test_infer_rego_query_rule_comments_and_explicit_override() {
        let src = "# comment\npackage apodictic.treasury;\nimport rego.v1\nallow := true";
        assert_eq!(infer_rego_query_rule(src, None), "data.apodictic.treasury.allow");
        assert_eq!(
            infer_rego_query_rule(src, Some("data.custom.rule")),
            "data.custom.rule"
        );
        assert_eq!(infer_rego_query_rule("allow := true", None), "data.apodictic.allow");
    }
}
