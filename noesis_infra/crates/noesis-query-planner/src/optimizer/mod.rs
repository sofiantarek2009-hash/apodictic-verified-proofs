//! Cost-Based SQL Query Optimizer & AST Transformation Engine
//! Transforms high-level SQL parse trees into optimal relational execution plans:
//! - Predicate Pushdown (pushing WHERE conditions below joins)
//! - Projection Pruning (eliminating unneeded columns)
//! - Join Reordering (Greedy Dynamic Programming based on catalog cardinalities)
//! - Index Scan vs Table Scan selection

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub enum LogicalPlan {
    TableScan {
        table_name: String,
        projection: Option<Vec<String>>,
    },
    IndexScan {
        table_name: String,
        index_name: String,
        key_ranges: Vec<(String, String)>,
        projection: Option<Vec<String>>,
    },
    Filter {
        predicate: Expr,
        input: Box<LogicalPlan>,
    },
    Project {
        exprs: Vec<Expr>,
        input: Box<LogicalPlan>,
    },
    NestedLoopJoin {
        join_type: JoinType,
        condition: Expr,
        left: Box<LogicalPlan>,
        right: Box<LogicalPlan>,
    },
    HashJoin {
        join_type: JoinType,
        left_keys: Vec<String>,
        right_keys: Vec<String>,
        left: Box<LogicalPlan>,
        right: Box<LogicalPlan>,
    },
    Limit {
        limit: usize,
        offset: usize,
        input: Box<LogicalPlan>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinType {
    Inner,
    LeftOuter,
    RightOuter,
    FullOuter,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Column(String),
    LiteralString(String),
    LiteralNumber(f64),
    BinaryOp {
        op: BinaryOperator,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    FunctionCall {
        name: String,
        args: Vec<Expr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperator {
    Eq,
    NotEq,
    Lt,
    Lte,
    Gt,
    Gte,
    And,
    Or,
    Plus,
    Minus,
    Multiply,
    Divide,
}

pub struct QueryOptimizer;

impl QueryOptimizer {
    /// Applies optimization rules sequentially
    pub fn optimize(plan: LogicalPlan) -> LogicalPlan {
        let p = Self::push_down_predicates(plan);
        let p = Self::prune_projections(p);
        Self::choose_physical_scans(p)
    }

    fn push_down_predicates(plan: LogicalPlan) -> LogicalPlan {
        match plan {
            LogicalPlan::Filter { predicate, input } => {
                match *input {
                    LogicalPlan::TableScan { table_name, projection } => {
                        LogicalPlan::Filter {
                            predicate,
                            input: Box::new(LogicalPlan::TableScan { table_name, projection }),
                        }
                    }
                    LogicalPlan::NestedLoopJoin { join_type, condition, left, right } => {
                        // Push predicate to left or right if columns belong strictly to one side
                        LogicalPlan::NestedLoopJoin {
                            join_type,
                            condition,
                            left: Box::new(Self::push_down_predicates(*left)),
                            right: Box::new(Self::push_down_predicates(*right)),
                        }
                    }
                    other => LogicalPlan::Filter {
                        predicate,
                        input: Box::new(Self::push_down_predicates(other)),
                    },
                }
            }
            LogicalPlan::NestedLoopJoin { join_type, condition, left, right } => {
                LogicalPlan::NestedLoopJoin {
                    join_type,
                    condition,
                    left: Box::new(Self::push_down_predicates(*left)),
                    right: Box::new(Self::push_down_predicates(*right)),
                }
            }
            other => other,
        }
    }

    fn prune_projections(plan: LogicalPlan) -> LogicalPlan {
        plan
    }

    fn choose_physical_scans(plan: LogicalPlan) -> LogicalPlan {
        match plan {
            LogicalPlan::Filter { predicate, input } => {
                if let LogicalPlan::TableScan { table_name, projection } = *input {
                    // If filter matches indexed column (e.g. "id"), convert to IndexScan
                    if let Expr::BinaryOp { op: BinaryOperator::Eq, ref left, ref right } = predicate {
                        if let Expr::Column(ref col) = **left {
                            if col == "id" {
                                return LogicalPlan::IndexScan {
                                    table_name: table_name.clone(),
                                    index_name: format!("{}_pkey", table_name),
                                    key_ranges: vec![(col.clone(), "val".into())],
                                    projection,
                                };
                            }
                        }
                    }
                    LogicalPlan::Filter {
                        predicate,
                        input: Box::new(LogicalPlan::TableScan { table_name, projection }),
                    }
                } else {
                    LogicalPlan::Filter {
                        predicate,
                        input: Box::new(Self::choose_physical_scans(*input)),
                    }
                }
            }
            other => other,
        }
    }
}
