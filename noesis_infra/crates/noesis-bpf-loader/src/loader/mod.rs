use std::path::Path;
use thiserror::Error;
use crate::maps::{BpfMapDef, BpfMapType, UserspaceBpfMap};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("ELF format error: {0}")]
    ElfFormatError(String),
    #[error("Map initialization failed: {0}")]
    MapError(String),
    #[error("XDP attach failure on interface {interface}: {code}")]
    XdpAttachFailed { interface: String, code: i32 },
}

pub enum XdpAttachMode {
    Generic,
    Driver,
    Offload,
}

pub struct XdpProgram {
    pub name: String,
    pub insn_count: usize,
    pub bytecode: Vec<u8>,
}

pub struct BpfObject {
    pub programs: HashMap<String, XdpProgram>,
    pub maps: HashMap<String, Arc<UserspaceBpfMap>>,
}

impl BpfObject {
    pub fn from_elf_bytes(elf: &[u8]) -> Result<Self, LoaderError> {
        if elf.len() < 4 || &elf[0..4] != b"\x7fELF" {
            return Err(LoaderError::ElfFormatError("Invalid ELF magic header".into()));
        }

        let mut maps = HashMap::new();
        // Setup standard Apodictic transparent proxy drop/intercept maps
        let blocked_ips_def = BpfMapDef {
            name: "blocked_ips".into(),
            map_type: BpfMapType::LruHashMap,
            key_size: 4, // IPv4 address
            value_size: 8, // timestamp + drop count
            max_entries: 65536,
            flags: 0,
        };
        maps.insert("blocked_ips".into(), Arc::new(UserspaceBpfMap::new(blocked_ips_def)));

        let port_routing_def = BpfMapDef {
            name: "port_routing".into(),
            map_type: BpfMapType::Hash,
            key_size: 2, // Port (u16)
            value_size: 4, // Target redirect port or proxy action
            max_entries: 1024,
            flags: 0,
        };
        maps.insert("port_routing".into(), Arc::new(UserspaceBpfMap::new(port_routing_def)));

        let mut programs = HashMap::new();
        programs.insert("xdp_noesis_filter".into(), XdpProgram {
            name: "xdp_noesis_filter".into(),
            insn_count: elf.len() / 8,
            bytecode: elf.to_vec(),
        });

        Ok(Self { programs, maps })
    }

    pub fn attach_xdp(&self, interface: &str, _mode: XdpAttachMode) -> Result<u32, LoaderError> {
        if interface.is_empty() {
            return Err(LoaderError::XdpAttachFailed {
                interface: interface.into(),
                code: -19, // ENODEV
            });
        }
        // Returns simulated XDP link ID
        Ok(42)
    }
}
