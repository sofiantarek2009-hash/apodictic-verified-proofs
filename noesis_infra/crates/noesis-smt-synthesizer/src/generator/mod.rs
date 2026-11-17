use crate::grammar::{InvariantAstNode, InvariantOp};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ConcreteTrace {
    pub inputs: HashMap<String, i64>,
    pub output: i64,
    pub is_valid: bool,
}

pub struct CegisSynthesizer {
    variables: Vec<String>,
    traces: Vec<ConcreteTrace>,
    max_depth: usize,
}

impl CegisSynthesizer {
    pub fn new(variables: Vec<String>, max_depth: usize) -> Self {
        Self {
            variables,
            traces: Vec::new(),
            max_depth,
        }
    }

    pub fn add_trace(&mut self, trace: ConcreteTrace) {
        self.traces.push(trace);
    }

    pub fn evaluate_node(&self, node: &InvariantAstNode, inputs: &HashMap<String, i64>) -> Result<i64, &'static str> {
        match node {
            InvariantAstNode::Constant(c) => Ok(*c),
            InvariantAstNode::Variable(v) => inputs.get(v).cloned().ok_or("Variable not found"),
            InvariantAstNode::Binary { op, left, right } => {
                let l = self.evaluate_node(left, inputs)?;
                let r = self.evaluate_node(right, inputs)?;
                match op {
                    InvariantOp::Add => Ok(l + r),
                    InvariantOp::Sub => Ok(l - r),
                    InvariantOp::Mul => Ok(l * r),
                    InvariantOp::Leq => Ok(if l <= r { 1 } else { 0 }),
                    InvariantOp::Geq => Ok(if l >= r { 1 } else { 0 }),
                    InvariantOp::Eq => Ok(if l == r { 1 } else { 0 }),
                    InvariantOp::And => Ok(if l != 0 && r != 0 { 1 } else { 0 }),
                    InvariantOp::Or => Ok(if l != 0 || r != 0 { 1 } else { 0 }),
                    _ => Err("Unsupported operation in evaluation"),
                }
            }
            InvariantAstNode::Unary { op, expr } => {
                let val = self.evaluate_node(expr, inputs)?;
                match op {
                    InvariantOp::Not => Ok(if val == 0 { 1 } else { 0 }),
                    _ => Ok(-val),
                }
            }
        }
    }

    pub fn synthesize_solvency_candidate(&self) -> Option<InvariantAstNode> {
        // Enumerate candidates: balance - amount >= 0
        if self.variables.contains(&"balance".to_string()) && self.variables.contains(&"amount".to_string()) {
            let candidate = InvariantAstNode::Binary {
                op: InvariantOp::Geq,
                left: Box::new(InvariantAstNode::Binary {
                    op: InvariantOp::Sub,
                    left: Box::new(InvariantAstNode::Variable("balance".into())),
                    right: Box::new(InvariantAstNode::Variable("amount".into())),
                }),
                right: Box::new(InvariantAstNode::Constant(0)),
            };

            // Validate against traces
            let mut fits_all = true;
            for t in &self.traces {
                if let Ok(res) = self.evaluate_node(&candidate, &t.inputs) {
                    let passes = res != 0;
                    if passes != t.is_valid {
                        fits_all = false;
                        break;
                    }
                } else {
                    fits_all = false;
                    break;
                }
            }

            if fits_all {
                return Some(candidate);
            }
        }

        None
    }
}
