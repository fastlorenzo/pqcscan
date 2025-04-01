#![allow(unused)]

use anyhow::{anyhow, Result};
use crate::utils::{ScanOptions, Target};
use crate::Config;
use crate::result::{Scan, ScanResult};
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

async fn ssh_scan_target(config: &Arc<Config>, target: &Target) -> ScanResult {
    log::debug!("Started scanning {}", target);

    let addrs_resolved = format!("{0}:{1}", target.host, target.port).to_socket_addrs();
    if addrs_resolved.is_err() {
        log::trace!("Could not resolve {target}: {:?}", addrs_resolved.err());
        return ScanResult::Ssh {
            targetspec: target.clone(),
            addr: None,
            error: Some(format!("Could not resolve {}", target.host)),
            pqc_supported: false,
            pqc_algos: None,
            nonpqc_algos: None,
        };
    }
    let addr = addrs_resolved.unwrap().next();
    if addr.is_none() {
        log::trace!("Could not resolve {target}. No addresses returned");
        return ScanResult::Ssh {
            targetspec: target.clone(),
            addr: None,
            error: Some(format!("Could not resolve {}", target.host)),
            pqc_supported: false,
            pqc_algos: None,
            nonpqc_algos: None,
        };
    }

    let addr = addr.unwrap();
    log::trace!("Resolved {0} to {1}", target, addr);

    let socket = TcpSocket::new_v4().unwrap();
    let connect_result = socket.connect(addr).await;
    if connect_result.is_err() {
        log::trace!("Could not connect to {addr}");
        return ScanResult::Ssh {
            targetspec: target.clone(),
            addr: Some(addr.to_string()),
            error: Some(format!("Could not connect to {addr}")),
            pqc_supported: false,
            pqc_algos: None,
            nonpqc_algos: None,
        };
    }

    log::trace!("Connected to {addr}");
    let stream = connect_result.unwrap();
    
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
                            log::warn!("PQC Algorithm supported: {}", k);
                            pqc_supported = true;
                            pqc_algos.push(k);
                        }
                        else {
                            log::trace!("Non-PQC Algorithm supported: {}", k);
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

pub async fn ssh_scan(config: Arc<Config>, scan: ScanOptions) -> Scan {

    let (tx, rx_orig) = async_channel::unbounded();
    let (results_tx_orig, results_rx) = async_channel::unbounded();
    let targets_cnt = scan.targets.len();

    /* no need to have more threads than targets */
    let mut num_threads = scan.num_threads;
    if num_threads > targets_cnt {
        num_threads = targets_cnt;
    }

    let start_time = Utc::now();

    /* send all targets into the channel and end with
     * empty targets as a signal for the tasks to exit
     * cleanly. */
    for target in scan.targets {
        log::trace!("Sending {}", target);
        if let Err(_) = tx.send(target).await {
            log::error!("thread dropped");
        }
    }
    for _ in 0..num_threads {
        if let Err(_) = tx.send(Target { host: "".to_string(), port: 0 }).await {
            log::error!("Thread dropped");
        }
    }

    log::trace!("Spawning {} Thread", num_threads);
    for no in 1..num_threads+1 {

        log::trace!("Spawning SSH Scan Thread {}", no);

        let rx = rx_orig.clone();
        let results_tx = results_tx_orig.clone();
        let config = config.clone();
        tokio::spawn(async move {
            loop {
                while let Ok(target) = rx.recv().await {

                    /* empty host for a Target means we are asked to quit */
                    if target.host.len() == 0 {
                        log::trace!("Exit requested for SSH Scan Thread {}", no);
                        let _ = results_tx.send(ScanResult::Done).await;
                        break;
                    }

                    let result = ssh_scan_target(&config, &target).await;
                    let _ = results_tx.send(result).await;
                }

                log::trace!("Exiting SSH Scan Thread {}", no);
                break;
            }
        });
    }

    let mut results: Vec<ScanResult> = vec![];

    while let Ok(result) = results_rx.recv().await {
        match result {
            ScanResult::Done => {
                num_threads -= 1;
                if num_threads == 0 {
                    break;
                }
            }
            _ => {
                results.push(result);
            }
        }
    }

    let scan = Scan {
       results: results,
       start_time: start_time,
       end_time: Utc::now()
    };

    log::info!("Done scanning. All threads exited.");

    return scan;
}
