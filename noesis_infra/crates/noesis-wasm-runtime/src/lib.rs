pub mod memory;
pub mod linker;
pub mod instance;

pub use memory::{LinearMemory, MemoryError, WASM_PAGE_SIZE};
pub use linker::{Linker, WasmValue, HostFn};
pub use instance::{WasmInstance, WasmModule, WasmExecError};
