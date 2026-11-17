//! Relational Database Catalog & System Schema Schema
//! Tracks table metadata, primary/foreign keys, B-tree indexes, and statistics.

use std::collections::HashMap;
use parking_lot::RwLock;

#[derive(Debug, Clone)]
pub struct ColumnCatalog {
    pub name: String,
    pub data_type: DataType,
    pub is_nullable: bool,
    pub is_primary_key: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataType {
    Int32,
    Int64,
    Float64,
    String,
    Boolean,
    Timestamp,
}

#[derive(Debug, Clone)]
pub struct TableCatalog {
    pub name: String,
    pub columns: Vec<ColumnCatalog>,
    pub estimated_row_count: u64,
    pub indexes: Vec<String>,
}

pub struct SystemCatalog {
    tables: RwLock<HashMap<String, TableCatalog>>,
}

impl SystemCatalog {
    pub fn new() -> Self {
        let mut map = HashMap::new();

        // Default enterprise system tables
        map.insert(
            "accounts".into(),
            TableCatalog {
                name: "accounts".into(),
                columns: vec![
                    ColumnCatalog { name: "id".into(), data_type: DataType::Int64, is_nullable: false, is_primary_key: true },
                    ColumnCatalog { name: "balance".into(), data_type: DataType::Float64, is_nullable: false, is_primary_key: false },
                    ColumnCatalog { name: "currency".into(), data_type: DataType::String, is_nullable: false, is_primary_key: false },
                ],
                estimated_row_count: 50_000,
                indexes: vec!["accounts_pkey".into()],
            },
        );

        map.insert(
            "payroll_records".into(),
            TableCatalog {
                name: "payroll_records".into(),
                columns: vec![
                    ColumnCatalog { name: "id".into(), data_type: DataType::Int64, is_nullable: false, is_primary_key: true },
                    ColumnCatalog { name: "batch_id".into(), data_type: DataType::String, is_nullable: false, is_primary_key: false },
                    ColumnCatalog { name: "amount".into(), data_type: DataType::Float64, is_nullable: false, is_primary_key: false },
                    ColumnCatalog { name: "status".into(), data_type: DataType::String, is_nullable: false, is_primary_key: false },
                ],
                estimated_row_count: 100_000,
                indexes: vec!["payroll_pkey".into(), "payroll_batch_idx".into()],
            },
        );

        Self {
            tables: RwLock::new(map),
        }
    }

    pub fn get_table(&self, name: &str) -> Option<TableCatalog> {
        self.tables.read().get(name).cloned()
    }
}
