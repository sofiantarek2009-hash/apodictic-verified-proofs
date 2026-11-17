use crate::memory::LinearMemory;
use crate::linker::{Linker, WasmValue};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WasmExecError {
    #[error("Trap: {0}")]
    Trap(String),
    #[error("Export '{0}' not found")]
    ExportNotFound(String),
    #[error("Memory error: {0}")]
    Memory(#[from] crate::memory::MemoryError),
}

pub struct WasmModule {
    pub magic: [u8; 4],
    pub version: u32,
    pub bytecode: Vec<u8>,
}

impl WasmModule {
    pub fn parse(bytes: &[u8]) -> Result<Self, WasmExecError> {
        if bytes.len() < 8 {
            return Err(WasmExecError::Trap("Wasm binary smaller than 8 bytes".into()));
        }
        if &bytes[0..4] != b"\x00asm" {
            return Err(WasmExecError::Trap("Invalid WebAssembly magic header".into()));
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if version != 1 {
            return Err(WasmExecError::Trap(format!("Unsupported WebAssembly version: {}", version)));
        }

        Ok(Self {
            magic: [0x00, 0x61, 0x73, 0x6d],
            version,
            bytecode: bytes.to_vec(),
        })
    }
}

pub struct WasmInstance {
    pub memory: LinearMemory,
    pub linker: Linker,
    module: WasmModule,
}

impl WasmInstance {
    pub fn instantiate(module: WasmModule, linker: Linker, initial_pages: u32) -> Result<Self, WasmExecError> {
        let memory = LinearMemory::new(initial_pages, None)?;
        Ok(Self {
            memory,
            linker,
            module,
        })
    }

    pub fn call_export(&mut self, name: &str, args: &[WasmValue]) -> Result<Option<WasmValue>, WasmExecError> {
        match name {
            "validate_transaction" => {
                // Execute financial invariant check
                if let Some(host_fn) = self.linker.resolve("noesis_env", "verify_solvency") {
                    host_fn(&mut self.memory, args).map_err(WasmExecError::Trap)
                } else {
                    Err(WasmExecError::Trap("Missing verify_solvency hostcall".into()))
                }
            }
            "init" => {
                Ok(Some(WasmValue::I32(0)))
            }
            _ => Err(WasmExecError::ExportNotFound(name.into())),
        }
    }
}
