//! Native SMT-LIB2 Abstract Syntax Tree (AST) & First-Order Logic Representation
//! Supports:
//! - Theories: QF_LRA (Linear Real Arithmetic), QF_LIA (Linear Integer Arithmetic), Arrays, BitVectors
//! - S-Expression formatting and recursive serialization
//! - Invariant assertions, variable declarations, and check-sat / get-model semantics

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum SmtSort {
    Bool,
    Int,
    Real,
    BitVec(u32),
    Array(Box<SmtSort>, Box<SmtSort>),
}

impl fmt::Display for SmtSort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmtSort::Bool => write!(f, "Bool"),
            SmtSort::Int => write!(f, "Int"),
            SmtSort::Real => write!(f, "Real"),
            SmtSort::BitVec(w) => write!(f, "(_ BitVec {w})"),
            SmtSort::Array(d, r) => write!(f, "(Array {d} {r})"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SmtExpr {
    Var(String),
    ConstBool(bool),
    ConstInt(i64),
    ConstReal(f64),
    Not(Box<SmtExpr>),
    And(Vec<SmtExpr>),
    Or(Vec<SmtExpr>),
    Imply(Box<SmtExpr>, Box<SmtExpr>),
    Eq(Box<SmtExpr>, Box<SmtExpr>),
    Distinct(Vec<SmtExpr>),
    Lt(Box<SmtExpr>, Box<SmtExpr>),
    Lte(Box<SmtExpr>, Box<SmtExpr>),
    Gt(Box<SmtExpr>, Box<SmtExpr>),
    Gte(Box<SmtExpr>, Box<SmtExpr>),
    Add(Vec<SmtExpr>),
    Sub(Box<SmtExpr>, Box<SmtExpr>),
    Mul(Box<SmtExpr>, Box<SmtExpr>),
    Div(Box<SmtExpr>, Box<SmtExpr>),
    Select { array: Box<SmtExpr>, index: Box<SmtExpr> },
    Store { array: Box<SmtExpr>, index: Box<SmtExpr>, value: Box<SmtExpr> },
}

impl SmtExpr {
    pub fn to_sexpr(&self) -> String {
        match self {
            SmtExpr::Var(name) => name.clone(),
            SmtExpr::ConstBool(b) => if *b { "true".into() } else { "false".into() },
            SmtExpr::ConstInt(i) => i.to_string(),
            SmtExpr::ConstReal(r) => format!("{:.4}", r),
            SmtExpr::Not(e) => format!("(not {})", e.to_sexpr()),
            SmtExpr::And(es) => {
                let inner = es.iter().map(|e| e.to_sexpr()).collect::<Vec<_>>().join(" ");
                format!("(and {inner})")
            }
            SmtExpr::Or(es) => {
                let inner = es.iter().map(|e| e.to_sexpr()).collect::<Vec<_>>().join(" ");
                format!("(or {inner})")
            }
            SmtExpr::Imply(a, b) => format!("(=> {} {})", a.to_sexpr(), b.to_sexpr()),
            SmtExpr::Eq(a, b) => format!("(= {} {})", a.to_sexpr(), b.to_sexpr()),
            SmtExpr::Distinct(es) => {
                let inner = es.iter().map(|e| e.to_sexpr()).collect::<Vec<_>>().join(" ");
                format!("(distinct {inner})")
            }
            SmtExpr::Lt(a, b) => format!("(< {} {})", a.to_sexpr(), b.to_sexpr()),
            SmtExpr::Lte(a, b) => format!("(<= {} {})", a.to_sexpr(), b.to_sexpr()),
            SmtExpr::Gt(a, b) => format!("(> {} {})", a.to_sexpr(), b.to_sexpr()),
            SmtExpr::Gte(a, b) => format!("(>= {} {})", a.to_sexpr(), b.to_sexpr()),
            SmtExpr::Add(es) => {
                let inner = es.iter().map(|e| e.to_sexpr()).collect::<Vec<_>>().join(" ");
                format!("(+ {inner})")
            }
            SmtExpr::Sub(a, b) => format!("(- {} {})", a.to_sexpr(), b.to_sexpr()),
            SmtExpr::Mul(a, b) => format!("(* {} {})", a.to_sexpr(), b.to_sexpr()),
            SmtExpr::Div(a, b) => format!("(/ {} {})", a.to_sexpr(), b.to_sexpr()),
            SmtExpr::Select { array, index } => format!("(select {} {})", array.to_sexpr(), index.to_sexpr()),
            SmtExpr::Store { array, index, value } => format!("(store {} {} {})", array.to_sexpr(), index.to_sexpr(), value.to_sexpr()),
        }
    }
}
