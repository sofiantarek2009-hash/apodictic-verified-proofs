use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InvariantOp {
    Add,
    Sub,
    Mul,
    Leq,
    Geq,
    Eq,
    And,
    Or,
    Not,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InvariantAstNode {
    Constant(i64),
    Variable(String),
    Binary {
        op: InvariantOp,
        left: Box<InvariantAstNode>,
        right: Box<InvariantAstNode>,
    },
    Unary {
        op: InvariantOp,
        expr: Box<InvariantAstNode>,
    },
}

impl InvariantAstNode {
    pub fn to_smtlib2(&self) -> String {
        match self {
            InvariantAstNode::Constant(c) => c.to_string(),
            InvariantAstNode::Variable(v) => v.clone(),
            InvariantAstNode::Binary { op, left, right } => {
                let op_str = match op {
                    InvariantOp::Add => "+",
                    InvariantOp::Sub => "-",
                    InvariantOp::Mul => "*",
                    InvariantOp::Leq => "<=",
                    InvariantOp::Geq => ">=",
                    InvariantOp::Eq => "=",
                    InvariantOp::And => "and",
                    InvariantOp::Or => "or",
                    InvariantOp::Not => "not",
                };
                format!("({} {} {})", op_str, left.to_smtlib2(), right.to_smtlib2())
            }
            InvariantAstNode::Unary { op, expr } => {
                let op_str = match op {
                    InvariantOp::Not => "not",
                    _ => "-",
                };
                format!("({} {})", op_str, expr.to_smtlib2())
            }
        }
    }
}
