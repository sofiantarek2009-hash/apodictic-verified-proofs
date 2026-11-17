use crate::memory::{LinearMemory, MemoryError};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::Mutex;

#[derive(Debug, Clone, PartialEq)]
pub enum WasmValue {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
}

pub type HostFn = Arc<dyn Fn(&mut LinearMemory, &[WasmValue]) -> Result<Option<WasmValue>, String> + Send + Sync>;

pub struct Linker {
    imports: HashMap<(String, String), HostFn>,
}

impl Linker {
    pub fn new() -> Self {
        let mut linker = Self {
            imports: HashMap::new(),
        };
        linker.register_default_hostcalls();
        linker
    }

    pub fn register<F>(&mut self, module: &str, field: &str, func: F)
    where
        F: Fn(&mut LinearMemory, &[WasmValue]) -> Result<Option<WasmValue>, String> + Send + Sync + 'static,
    {
        self.imports.insert((module.to_string(), field.to_string()), Arc::new(func));
    }

    pub fn resolve(&self, module: &str, field: &str) -> Option<HostFn> {
        self.imports.get(&(module.to_string(), field.to_string())).cloned()
    }

    fn register_default_hostcalls(&mut self) {
        // noesis_env.verify_solvency(account_id, amount_cents) -> i32 (1 = ok, 0 = fail)
        self.register("noesis_env", "verify_solvency", |_mem, args| {
            if args.len() < 2 {
                return Err("verify_solvency requires 2 args".into());
            }
            let _account = match args[0] {
                WasmValue::I32(a) => a,
                _ => return Err("account_id must be i32".into()),
            };
            let amount = match args[1] {
                WasmValue::I64(v) => v,
                _ => return Err("amount must be i64".into()),
            };

            // Solvency rule: amount cannot be negative and cannot exceed $10,000,000.00
            if amount < 0 || amount > 1_000_000_000 {
                Ok(Some(WasmValue::I32(0)))
            } else {
                Ok(Some(WasmValue::I32(1)))
            }
        });

        // noesis_env.log_receipt(ptr, len) -> ()
        self.register("noesis_env", "log_receipt", |mem, args| {
            if args.len() < 2 {
                return Err("log_receipt requires ptr and len".into());
            }
            let ptr = match args[0] {
                WasmValue::I32(p) => p as usize,
                _ => return Err("ptr must be i32".into()),
            };
            let len = match args[1] {
                WasmValue::I32(l) => l as usize,
                _ => return Err("len must be i32".into()),
            };
            let _bytes = mem.read(ptr, len).map_err(|e| format!("{:?}", e))?;
            Ok(None)
        });
    }
}
