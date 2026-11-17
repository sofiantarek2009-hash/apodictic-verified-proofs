//! TLS 1.3 State Machine & Handshake Protocol Parser (RFC 8446)
//! Handshake Message Types:
//! - ClientHello (1), ServerHello (2), NewSessionTicket (4), EndOfEarlyData (5),
//!   EncryptedExtensions (8), Certificate (11), CertificateRequest (13),
//!   CertificateVerify (15), Finished (20), KeyUpdate (24)
//! Extensions:
//! - server_name (0), supported_groups (10), signature_algorithms (13),
//!   alpn (16), key_share (51), supported_versions (43)

use std::collections::HashMap;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use anyhow::{bail, Context, Result};

pub const HANDSHAKE_CLIENT_HELLO: u8 = 1;
pub const HANDSHAKE_SERVER_HELLO: u8 = 2;
pub const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HANDSHAKE_CERTIFICATE: u8 = 11;
pub const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 15;
pub const HANDSHAKE_FINISHED: u8 = 20;

pub const EXT_SERVER_NAME: u16 = 0;
pub const EXT_SUPPORTED_GROUPS: u16 = 10;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub const EXT_ALPN: u16 = 16;
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_KEY_SHARE: u16 = 51;

pub const TLS_1_3_VERSION: u16 = 0x0304;

#[derive(Debug, Clone)]
pub struct ClientHelloMessage {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub legacy_session_id: Bytes,
    pub cipher_suites: Vec<u16>,
    pub legacy_compression_methods: Vec<u8>,
    pub server_name: Option<String>,
    pub supported_versions: Vec<u16>,
    pub key_shares: Vec<(u16, Bytes)>, // (named_group, key_exchange_bytes)
    pub alpn_protocols: Vec<String>,
}

pub struct HandshakeParser;

impl HandshakeParser {
    pub fn parse_client_hello(mut buf: Bytes) -> Result<ClientHelloMessage> {
        if buf.len() < 38 {
            bail!("ClientHello payload too short");
        }

        let legacy_version = buf.get_u16();
        let mut random = [0u8; 32];
        buf.copy_to_slice(&mut random);

        let sess_len = buf.get_u8() as usize;
        if buf.remaining() < sess_len {
            bail!("Truncated session ID in ClientHello");
        }
        let legacy_session_id = buf.split_to(sess_len);

        let cipher_suites_len = buf.get_u16() as usize;
        if buf.remaining() < cipher_suites_len {
            bail!("Truncated cipher suites in ClientHello");
        }
        let mut cipher_suites = Vec::with_capacity(cipher_suites_len / 2);
        let mut cs_bytes = buf.split_to(cipher_suites_len);
        while cs_bytes.has_remaining() {
            cipher_suites.push(cs_bytes.get_u16());
        }

        let comp_len = buf.get_u8() as usize;
        if buf.remaining() < comp_len {
            bail!("Truncated compression methods in ClientHello");
        }
        let legacy_compression_methods = buf.split_to(comp_len).to_vec();

        let mut server_name = None;
        let mut supported_versions = Vec::new();
        let mut key_shares = Vec::new();
        let mut alpn_protocols = Vec::new();

        if buf.remaining() >= 2 {
            let extensions_len = buf.get_u16() as usize;
            if buf.remaining() < extensions_len {
                bail!("Truncated extensions section in ClientHello");
            }
            let mut ext_buf = buf.split_to(extensions_len);

            while ext_buf.remaining() >= 4 {
                let ext_type = ext_buf.get_u16();
                let ext_len = ext_buf.get_u16() as usize;
                if ext_buf.remaining() < ext_len {
                    bail!("Truncated extension block");
                }
                let mut data = ext_buf.split_to(ext_len);

                match ext_type {
                    EXT_SERVER_NAME => {
                        if data.remaining() >= 5 {
                            let _list_len = data.get_u16();
                            let name_type = data.get_u8();
                            if name_type == 0 {
                                let name_len = data.get_u16() as usize;
                                if data.remaining() >= name_len {
                                    let name_bytes = data.split_to(name_len);
                                    server_name = String::from_utf8(name_bytes.to_vec()).ok();
                                }
                            }
                        }
                    }
                    EXT_SUPPORTED_VERSIONS => {
                        if data.remaining() >= 1 {
                            let v_len = data.get_u8() as usize;
                            let mut v_data = data.split_to(v_len.min(data.remaining()));
                            while v_data.remaining() >= 2 {
                                supported_versions.push(v_data.get_u16());
                            }
                        }
                    }
                    EXT_ALPN => {
                        if data.remaining() >= 2 {
                            let _proto_list_len = data.get_u16();
                            while data.remaining() >= 1 {
                                let p_len = data.get_u8() as usize;
                                if data.remaining() >= p_len {
                                    let p_bytes = data.split_to(p_len);
                                    if let Ok(proto_str) = String::from_utf8(p_bytes.to_vec()) {
                                        alpn_protocols.push(proto_str);
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    EXT_KEY_SHARE => {
                        if data.remaining() >= 2 {
                            let _client_shares_len = data.get_u16();
                            while data.remaining() >= 4 {
                                let group = data.get_u16();
                                let key_len = data.get_u16() as usize;
                                if data.remaining() >= key_len {
                                    let k_bytes = data.split_to(key_len);
                                    key_shares.push((group, k_bytes));
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(ClientHelloMessage {
            legacy_version,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            server_name,
            supported_versions,
            key_shares,
            alpn_protocols,
        })
    }
}
