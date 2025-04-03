#![allow(unused)]

use anyhow::{anyhow, Result};
use crate::utils::Target;
use crate::Config;
use crate::scan::{Scan, ScanResult};
use std::io::{ErrorKind, Seek, SeekFrom};
use tokio::net::{TcpSocket, TcpStream};
use std::net::ToSocketAddrs;
use std::io::{Read, Cursor};
use byteorder::{BigEndian, ReadBytesExt};
use rust_embed::RustEmbed;
use std::collections::HashMap;
use serde::Deserialize;
use std::sync::Arc;
use chrono::prelude::*;

use crate::utils::socket_create_and_connect;

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/support"]
#[include = "kex_algos.json"]
struct EmbeddedResources;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct KexAlgo {
    pqc: bool,
    broken: bool,
    hybrid: Option<bool>,
    desc: Option<String>,
    href: Option<String>
}

pub struct SshConfig {
    kex_algos: HashMap<String, KexAlgo>
}

impl SshConfig {
    pub fn new() -> SshConfig {
        SshConfig {
            kex_algos: Self::load_kex_algos()
        }
    }

    fn load_kex_algos() -> HashMap<String, KexAlgo> {
        let json_file = EmbeddedResources::get("kex_algos.json").unwrap();
        let json_data = std::str::from_utf8(json_file.data.as_ref()).unwrap();
        let kex_algos = serde_json::from_str(&json_data).unwrap();
        return kex_algos;
    }
}

struct KexInitMsg {
    kex_algos: Vec<String>,
    host_key_algos: Vec<String>
}

fn find_pqs_algos(kex_algos: &Vec<String>, kexinit: &KexInitMsg) {
    for kex_algo in &kexinit.kex_algos {
        if kex_algos.contains(&kex_algo) {
            log::debug!("Found PQC algorithm {}", kex_algo);
        }
    }
}

fn parse_ssh_name_list(c: &mut Cursor<&Vec<u8>>) -> Result<Vec<String>> {
    let sz: usize = c.read_u32::<BigEndian>().unwrap().try_into()?;

    let mut buf = vec![0u8; sz];
    c.read_exact(&mut buf)?;
    let algo_str = String::from_utf8(buf)?;

    let mut algos: Vec<String> = vec![];
    for algo in algo_str.split(',').collect::<Vec<_>>() {
        algos.push(algo.to_string());
    }

    Ok(algos)
}

fn parse_ssh_msg_kexinit(buf: &Vec<u8>) -> Result<KexInitMsg> {
    let bl: u32 = buf.len() as u32;
    if bl < 4 {
        return Err(anyhow!("less than 4 bytes in kexinit buf"));
    }
    let mut c = Cursor::new(buf);
    let pkt_size = c.read_u32::<BigEndian>()?;
    if bl - 4 < pkt_size {
        return Err(anyhow!("invalid packet length in kexinit buf"));
    }

    let padding_len: u64 = c.read_u8()?.into();

    /* check if SSH_MSG_KEXINIT (20) */
    let msg_type = c.read_u8()?;
    if msg_type != 20 {
        return Err(anyhow!("invalid SSH packet type"));
    }
    c.seek(SeekFrom::Current(16))?;

    let kex_algos = parse_ssh_name_list(&mut c)?;
    let srv_host_key_algos = parse_ssh_name_list(&mut c)?;
    let enc_algos_c2s = parse_ssh_name_list(&mut c)?;
    let enc_algos_s2c = parse_ssh_name_list(&mut c)?;
    let mac_algos_c2s = parse_ssh_name_list(&mut c)?;
    let mac_algos_s2c = parse_ssh_name_list(&mut c)?;
    let compress_algos_c2s = parse_ssh_name_list(&mut c)?;
    let compress_algos_s2c = parse_ssh_name_list(&mut c)?;
    let lang_c2s = parse_ssh_name_list(&mut c)?;
    let lang_s2c = parse_ssh_name_list(&mut c)?;

    let end_of_pkt = c.position() + padding_len + 5;
    if bl as u64 != end_of_pkt {
        return Err(anyhow!("invalid SSH_KEXINIT packet"));
    }

    Ok(KexInitMsg {
        kex_algos: kex_algos,
        host_key_algos: srv_host_key_algos
    })
}

async fn ssh_recv_kexinit(stream: &TcpStream) -> Result<KexInitMsg> {
    let mut buf = [0; 4096];
    loop {

        let readable = stream.readable().await;
        if readable.is_err() {
            continue;
        }

        match stream.try_read(&mut buf) {
            Ok(0) => {
                log::trace!("Zero bytes read. Connection closed.");
                break;
            },
            Ok(n) => {
                return parse_ssh_msg_kexinit(&buf[0..n].to_vec());
            }
            /* try again if we get EAGAIN */
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                log::trace!("Error while trying to read kexinit: {}", e);
                break;
            }
        }
    }

    Err(anyhow!("I/O error when receiving SSH_MSG_KEXINIT"))
}

async fn ssh_echoback_idstring(stream: &TcpStream) {
    /* read SSH identification string and just echo it back to the server so we are always
     * considered compatible */
    loop {

        let readable = stream.readable().await;
        if readable.is_err() {
            continue;
        }

        let mut buf = [0; 4096];
        match stream.try_read(&mut buf) {
            Ok(0) => {
            },
            Ok(n) => {
                stream.writable().await.unwrap();
                let _ = stream.try_write(&buf);
                break;
            }
            /* try again if we get EAGAIN */
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                log::trace!("{}", e);
                break;
            }
        }
    }
}

pub async fn ssh_scan_target(config: &Arc<Config>, target: &Target) -> ScanResult {
    log::debug!("Started SSH scanning {}", target);

    let ret = socket_create_and_connect(&target, config.connection_timeout).await;
    if ret.is_err() {
        log::trace!("Could not connect to {target}");
        return ScanResult::Ssh {
            targetspec: target.clone(),
            addr: None,
            error: Some(ret.unwrap_err().to_string()),
            pqc_supported: false,
            pqc_algos: None,
            nonpqc_algos: None,
        };
    }
    let (addr, stream) = ret.unwrap();
        
    ssh_echoback_idstring(&stream).await;

    let mut pqc_supported = false;
    let mut pqc_algos: Vec<String> = vec![];
    let mut nonpqc_algos: Vec<String> = vec![];

    match ssh_recv_kexinit(&stream).await {
        Err(e) => {
            log::debug!("Unexpected response from {}", target);
        }
        Ok(ki) => {
            let kex_algos = &config.ssh_config.kex_algos;

            for k in ki.kex_algos {

                match kex_algos.get(&k) {
                    None => {
                        log::error!("Unknown algorithm {} found", k);
                    },
                    Some(a) => {
                        if a.pqc {
                            log::debug!("PQC Algorithm supported: {}", k);
                            pqc_supported = true;
                            pqc_algos.push(k);
                        }
                        else {
                            log::debug!("Non-PQC Algorithm supported: {}", k);
                            nonpqc_algos.push(k);
                        }
                    }
                }
            }
        }
    }

    log::trace!("Finished scanning {}", target);
    let ret = ScanResult::Ssh {
        targetspec: target.clone(),
        addr: Some(addr.to_string()),
        error: None,
        pqc_supported: pqc_supported,
        pqc_algos: Some(pqc_algos),
        nonpqc_algos: Some(nonpqc_algos)
    };
    return ret;
}