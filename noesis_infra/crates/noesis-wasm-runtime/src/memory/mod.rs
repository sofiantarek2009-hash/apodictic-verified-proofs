use thiserror::Error;

pub const WASM_PAGE_SIZE: usize = 65536; // 64KiB per WebAssembly linear memory page
pub const MAX_WASM_PAGES: u32 = 1024; // 64MiB max sandbox allocation

#[derive(Debug, Error, PartialEq)]
pub enum MemoryError {
    #[error("Out of bounds memory access: offset {offset} + size {size} > total {total}")]
    OutOfBounds { offset: usize, size: usize, total: usize },
    #[error("Memory growth exceeded limits: requested {requested} pages, max {max}")]
    GrowthExceeded { requested: u32, max: u32 },
}

pub struct LinearMemory {
    data: Vec<u8>,
    current_pages: u32,
    max_pages: u32,
}

impl LinearMemory {
    pub fn new(initial_pages: u32, max_pages: Option<u32>) -> Result<Self, MemoryError> {
        let max = max_pages.unwrap_or(MAX_WASM_PAGES);
        if initial_pages > max {
            return Err(MemoryError::GrowthExceeded {
                requested: initial_pages,
                max,
            });
        }

        let total_bytes = initial_pages as usize * WASM_PAGE_SIZE;
        Ok(Self {
            data: vec![0u8; total_bytes],
            current_pages: initial_pages,
            max_pages: max,
        })
    }

    pub fn grow(&mut self, additional_pages: u32) -> Result<u32, MemoryError> {
        let old_pages = self.current_pages;
        let new_pages = old_pages + additional_pages;

        if new_pages > self.max_pages {
            return Err(MemoryError::GrowthExceeded {
                requested: new_pages,
                max: self.max_pages,
            });
        }

        let new_size = new_pages as usize * WASM_PAGE_SIZE;
        self.data.resize(new_size, 0);
        self.current_pages = new_pages;

        Ok(old_pages)
    }

    pub fn read(&self, offset: usize, size: usize) -> Result<&[u8], MemoryError> {
        if offset + size > self.data.len() {
            return Err(MemoryError::OutOfBounds {
                offset,
                size,
                total: self.data.len(),
            });
        }
        Ok(&self.data[offset..offset + size])
    }

    pub fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        if offset + bytes.len() > self.data.len() {
            return Err(MemoryError::OutOfBounds {
                offset,
                size: bytes.len(),
                total: self.data.len(),
            });
        }
        self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    pub fn read_u32(&self, offset: usize) -> Result<u32, MemoryError> {
        let bytes = self.read(offset, 4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn write_u32(&mut self, offset: usize, val: u32) -> Result<(), MemoryError> {
        self.write(offset, &val.to_le_bytes())
    }

    pub fn read_i64(&self, offset: usize) -> Result<i64, MemoryError> {
        let bytes = self.read(offset, 8)?;
        Ok(i64::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn write_i64(&mut self, offset: usize, val: i64) -> Result<(), MemoryError> {
        self.write(offset, &val.to_le_bytes())
    }

    pub fn current_size(&self) -> usize {
        self.data.len()
    }
}
