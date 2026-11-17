use crate::ast::*;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum EvalValue {
    Null,
    Boolean(bool),
    Integer(i64),
    Float(f64),
    String(String),
}

impl EvalValue {
    pub fn is_truthy(&self) -> bool {
        match self {
            EvalValue::Null => false,
            EvalValue::Boolean(b) => *b,
            EvalValue::Integer(i) => *i != 0,
            EvalValue::Float(f) => *f != 0.0,
            EvalValue::String(s) => !s.is_empty(),
        }
    }
}

pub struct ExpressionEvaluator<'a> {
    pub context: &'a HashMap<String, EvalValue>,
}

impl<'a> ExpressionEvaluator<'a> {
    pub fn new(context: &'a HashMap<String, EvalValue>) -> Self {
        Self { context }
    }

    pub fn eval(&self, expr: &Expression) -> Result<EvalValue, String> {
        match expr {
            Expression::Literal(lit) => match lit {
                LiteralValue::Null => Ok(EvalValue::Null),
                LiteralValue::Boolean(b) => Ok(EvalValue::Boolean(*b)),
                LiteralValue::Integer(i) => Ok(EvalValue::Integer(*i)),
                LiteralValue::Float(f) => Ok(EvalValue::Float(*f)),
                LiteralValue::String(s) => Ok(EvalValue::String(s.clone())),
            },
            Expression::Identifier(name) => {
                self.context.get(name)
                    .cloned()
                    .ok_or_else(|| format!("Column or variable '{}' not found in evaluation context", name))
            }
            Expression::QualifiedColumn { table: _, column } => {
                self.context.get(column)
                    .cloned()
                    .ok_or_else(|| format!("Qualified column '{}' not found in evaluation context", column))
            }
            Expression::BinaryOp { left, op, right } => {
                let l_val = self.eval(left)?;
                let r_val = self.eval(right)?;
                self.eval_binary_op(&l_val, op, &r_val)
            }
            Expression::UnaryOp { op, expr } => {
                let val = self.eval(expr)?;
                match op {
                    UnaryOperator::Not => Ok(EvalValue::Boolean(!val.is_truthy())),
                    UnaryOperator::IsNull => Ok(EvalValue::Boolean(val == EvalValue::Null)),
                    UnaryOperator::IsNotNull => Ok(EvalValue::Boolean(val != EvalValue::Null)),
                    UnaryOperator::Neg => match val {
                        EvalValue::Integer(i) => Ok(EvalValue::Integer(-i)),
                        EvalValue::Float(f) => Ok(EvalValue::Float(-f)),
                        _ => Err("Unary negation only applies to numbers".into()),
                    },
                }
            }
            Expression::FunctionCall { name, args } => {
                let mut evaluated_args = Vec::new();
                for arg in args {
                    evaluated_args.push(self.eval(arg)?);
                }
                self.eval_builtin_function(name, evaluated_args)
            }
            Expression::InList { expr, list, negated } => {
                let val = self.eval(expr)?;
                let mut found = false;
                for item in list {
                    let item_val = self.eval(item)?;
                    if val == item_val {
                        found = true;
                        break;
                    }
                }
                let res = if *negated { !found } else { found };
                Ok(EvalValue::Boolean(res))
            }
            _ => Err("Expression type not supported in evaluator".into()),
        }
    }

    fn eval_binary_op(&self, left: &EvalValue, op: &BinaryOperator, right: &EvalValue) -> Result<EvalValue, String> {
        match op {
            BinaryOperator::Eq => Ok(EvalValue::Boolean(left == right)),
            BinaryOperator::NotEq => Ok(EvalValue::Boolean(left != right)),
            BinaryOperator::And => Ok(EvalValue::Boolean(left.is_truthy() && right.is_truthy())),
            BinaryOperator::Or => Ok(EvalValue::Boolean(left.is_truthy() || right.is_truthy())),
            BinaryOperator::Plus => match (left, right) {
                (EvalValue::Integer(a), EvalValue::Integer(b)) => Ok(EvalValue::Integer(a + b)),
                (EvalValue::Float(a), EvalValue::Float(b)) => Ok(EvalValue::Float(a + b)),
                (EvalValue::Integer(a), EvalValue::Float(b)) => Ok(EvalValue::Float(*a as f64 + b)),
                (EvalValue::Float(a), EvalValue::Integer(b)) => Ok(EvalValue::Float(a + *b as f64)),
                _ => Err("Addition requires numeric operands".into()),
            },
            BinaryOperator::Minus => match (left, right) {
                (EvalValue::Integer(a), EvalValue::Integer(b)) => Ok(EvalValue::Integer(a - b)),
                (EvalValue::Float(a), EvalValue::Float(b)) => Ok(EvalValue::Float(a - b)),
                _ => Err("Subtraction requires numeric operands".into()),
            },
            BinaryOperator::Multiply => match (left, right) {
                (EvalValue::Integer(a), EvalValue::Integer(b)) => Ok(EvalValue::Integer(a * b)),
                (EvalValue::Float(a), EvalValue::Float(b)) => Ok(EvalValue::Float(a * b)),
                _ => Err("Multiplication requires numeric operands".into()),
            },
            BinaryOperator::Divide => match (left, right) {
                (EvalValue::Integer(a), EvalValue::Integer(b)) => {
                    if *b == 0 {
                        return Err("Division by zero".into());
                    }
                    Ok(EvalValue::Integer(a / b))
                }
                (EvalValue::Float(a), EvalValue::Float(b)) => {
                    if *b == 0.0 {
                        return Err("Division by zero".into());
                    }
                    Ok(EvalValue::Float(a / b))
                }
                _ => Err("Division requires numeric operands".into()),
            },
            BinaryOperator::Gt => match (left, right) {
                (EvalValue::Integer(a), EvalValue::Integer(b)) => Ok(EvalValue::Boolean(a > b)),
                (EvalValue::Float(a), EvalValue::Float(b)) => Ok(EvalValue::Boolean(a > b)),
                _ => Err("Comparison requires matching numeric types".into()),
            },
            BinaryOperator::Gte => match (left, right) {
                (EvalValue::Integer(a), EvalValue::Integer(b)) => Ok(EvalValue::Boolean(a >= b)),
                (EvalValue::Float(a), EvalValue::Float(b)) => Ok(EvalValue::Boolean(a >= b)),
                _ => Err("Comparison requires matching numeric types".into()),
            },
            BinaryOperator::Lt => match (left, right) {
                (EvalValue::Integer(a), EvalValue::Integer(b)) => Ok(EvalValue::Boolean(a < b)),
                (EvalValue::Float(a), EvalValue::Float(b)) => Ok(EvalValue::Boolean(a < b)),
                _ => Err("Comparison requires matching numeric types".into()),
            },
            BinaryOperator::Lte => match (left, right) {
                (EvalValue::Integer(a), EvalValue::Integer(b)) => Ok(EvalValue::Boolean(a <= b)),
                (EvalValue::Float(a), EvalValue::Float(b)) => Ok(EvalValue::Boolean(a <= b)),
                _ => Err("Comparison requires matching numeric types".into()),
            },
            _ => Err(format!("Operator {:?} not implemented", op)),
        }
    }

    fn eval_builtin_function(&self, name: &str, args: Vec<EvalValue>) -> Result<EvalValue, String> {
        let upper = name.to_uppercase();
        match upper.as_str() {
            "COALESCE" => {
                for arg in args {
                    if arg != EvalValue::Null {
                        return Ok(arg);
                    }
                }
                Ok(EvalValue::Null)
            }
            "LOWER" => match args.first() {
                Some(EvalValue::String(s)) => Ok(EvalValue::String(s.to_lowercase())),
                _ => Err("LOWER expects 1 string argument".into()),
            },
            "UPPER" => match args.first() {
                Some(EvalValue::String(s)) => Ok(EvalValue::String(s.to_uppercase())),
                _ => Err("UPPER expects 1 string argument".into()),
            },
            "ABS" => match args.first() {
                Some(EvalValue::Integer(i)) => Ok(EvalValue::Integer(i.abs())),
                Some(EvalValue::Float(f)) => Ok(EvalValue::Float(f.abs())),
                _ => Err("ABS expects 1 numeric argument".into()),
            },
            _ => Err(format!("Unknown function: {}", name)),
        }
    }
}
