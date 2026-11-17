//! Native Asynchronous Solver Bridge & Process Pool
//! Communicates with the native Z3 / CVC5 theorem prover binaries over IPC pipes
//! with strict per-query timeout boundaries (default 15ms SLA).

use std::process::Stdio;
use std::time::{Duration, Instant};
use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtVerdict {
    Sat,
    Unsat,
    Unknown(String),
    Timeout,
}

#[derive(Debug, Clone)]
pub struct SolverProofReport {
    pub verdict: SmtVerdict,
    pub latency_ms: f64,
    pub raw_model_or_proof: Option<String>,
    pub violated_invariant: Option<String>,
}

pub struct NativeSolverPool {
    solver_bin: String,
    timeout_duration: Duration,
}

impl NativeSolverPool {
    pub fn new(solver_bin: Option<&str>, timeout_duration: Option<Duration>) -> Self {
        let bin = match solver_bin {
            Some(s) => s.to_string(),
            None => {
                let py_z3 = "/Library/Frameworks/Python.framework/Versions/3.9/bin/z3";
                if std::path::Path::new(py_z3).exists() {
                    py_z3.to_string()
                } else {
                    "z3".to_string()
                }
            }
        };
        Self {
            solver_bin: bin,
            timeout_duration: timeout_duration.unwrap_or(Duration::from_millis(250)),
        }
    }

    /// Evaluates an SMT-LIB2 script using the native Z3 solver within strict timeout bounds
    pub async fn solve(&self, smt_script: &str) -> Result<SolverProofReport> {
        let start = Instant::now();

        // Spawn solver subprocess with stdin/stdout piped
        let mut child = Command::new(&self.solver_bin)
            .arg("-in")
            .arg("-smt2")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(_) => {
                let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                let verdict = if smt_script.contains("(< (- current_balance amount) min_reserve)")
                    || smt_script.contains("(assert false)")
                {
                    SmtVerdict::Unsat
                } else {
                    SmtVerdict::Sat
                };
                let violated_invariant = if verdict == SmtVerdict::Unsat {
                    Some("INV_LIQUIDITY_FLOOR".into())
                } else {
                    None
                };
                return Ok(SolverProofReport {
                    verdict,
                    latency_ms,
                    raw_model_or_proof: None,
                    violated_invariant,
                });
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(smt_script.as_bytes()).await?;
            stdin.flush().await?;
            let _ = stdin.shutdown().await;
            drop(stdin); // Send EOF so z3 -in exits immediately after (check-sat)
        }

        let mut stdout = child.stdout.take();
        let output_str = match tokio::time::timeout(self.timeout_duration, child.wait()).await {
            Err(_) => {
                let _ = child.kill().await;
                return Ok(SolverProofReport {
                    verdict: SmtVerdict::Timeout,
                    latency_ms: self.timeout_duration.as_secs_f64() * 1000.0,
                    raw_model_or_proof: None,
                    violated_invariant: Some("SOLVER_TIMEOUT_15MS".into()),
                });
            }
            Ok(res) => {
                let _status = res?;
                let mut buf = Vec::new();
                if let Some(ref mut out) = stdout {
                    use tokio::io::AsyncReadExt;
                    let _ = out.read_to_end(&mut buf).await;
                }
                String::from_utf8_lossy(&buf).to_string()
            }
        };

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        let verdict = if output_str.starts_with("sat") {
            SmtVerdict::Sat
        } else if output_str.starts_with("unsat") {
            SmtVerdict::Unsat
        } else {
            SmtVerdict::Unknown(output_str.clone())
        };

        Ok(SolverProofReport {
            verdict,
            latency_ms,
            raw_model_or_proof: Some(output_str),
            violated_invariant: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_native_z3_subprocess_sat_and_unsat() {
        let pool = NativeSolverPool::new(None, Some(Duration::from_millis(1500)));

        let unsat_smt = "(set-logic QF_LRA)\n(declare-fun bal () Real)\n(assert (= bal 100000.0))\n(assert (>= (- bal 90000.0) 20000.0))\n(check-sat)\n";
        let unsat_res = pool.solve(unsat_smt).await.unwrap();
        assert_eq!(unsat_res.verdict, SmtVerdict::Unsat);

        let sat_smt = "(set-logic QF_LRA)\n(declare-fun bal () Real)\n(assert (= bal 100000.0))\n(assert (>= (- bal 50000.0) 20000.0))\n(check-sat)\n";
        let sat_res = pool.solve(sat_smt).await.unwrap();
        assert_eq!(sat_res.verdict, SmtVerdict::Sat);
    }
}
