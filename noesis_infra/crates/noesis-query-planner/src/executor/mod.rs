//! Relational Volcano-Model Iterator Execution Engine
//! Evaluates physical query operators using pull-based `next()` tuples.

use std::collections::HashMap;
use anyhow::Result;
use bytes::Bytes;

#[derive(Debug, Clone, PartialEq)]
pub enum TupleValue {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Null,
}

pub type RecordTuple = Vec<TupleValue>;

pub trait PhysicalOperator: Send {
    fn open(&mut self) -> Result<()>;
    fn next(&mut self) -> Result<Option<RecordTuple>>;
    fn close(&mut self) -> Result<()>;
}

pub struct MemoryScanOperator {
    data: Vec<RecordTuple>,
    cursor: usize,
}

impl MemoryScanOperator {
    pub fn new(data: Vec<RecordTuple>) -> Self {
        Self { data, cursor: 0 }
    }
}

impl PhysicalOperator for MemoryScanOperator {
    fn open(&mut self) -> Result<()> {
        self.cursor = 0;
        Ok(())
    }

    fn next(&mut self) -> Result<Option<RecordTuple>> {
        if self.cursor < self.data.len() {
            let row = self.data[self.cursor].clone();
            self.cursor += 1;
            Ok(Some(row))
        } else {
            Ok(None)
        }
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

pub struct FilterOperator {
    input: Box<dyn PhysicalOperator>,
    predicate_col: usize,
    target_value: TupleValue,
}

impl FilterOperator {
    pub fn new(input: Box<dyn PhysicalOperator>, predicate_col: usize, target_value: TupleValue) -> Self {
        Self {
            input,
            predicate_col,
            target_value,
        }
    }
}

impl PhysicalOperator for FilterOperator {
    fn open(&mut self) -> Result<()> {
        self.input.open()
    }

    fn next(&mut self) -> Result<Option<RecordTuple>> {
        while let Some(row) = self.input.next()? {
            if row.get(self.predicate_col) == Some(&self.target_value) {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }

    fn close(&mut self) -> Result<()> {
        self.input.close()
    }
}
