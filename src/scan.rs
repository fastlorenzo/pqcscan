use crate::Target;
use serde::{Serialize, Deserialize};
use chrono::prelude::*;
use std::sync::Arc;

use crate::Config;
use crate::ssh::ssh_scan_target;
use crate::tls::tls_scan_target;

#[derive(Serialize, Deserialize, Clone)]
pub enum ScanResult {
    Ssh {
        targetspec: Target,
        addr: Option<String>,
        error: Option<String>,
        pqc_supported: bool,
        pqc_algos: Option<Vec<String>>,
        nonpqc_algos: Option<Vec<String>>
    },
    Tls {
        targetspec: Target,
        error: Option<String>,
        pqc_supported: bool,
        pqc_algos: Option<Vec<String>>,
        hybrid_algos: Option<Vec<String>>,
    },
    Done
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Scan {
    pub results: Vec<ScanResult>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>
}

#[derive(Clone, Copy)]
pub enum ScanType {
    Ssh,
    Tls
}

pub struct ScanOptions {
    pub num_threads: usize,
    pub targets: Vec<Target>,
    pub scan_type: Option<ScanType>,
}

pub async fn scan_runner(config: Arc<Config>, scan: ScanOptions) -> Scan {
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

        log::trace!("Spawning Scan Thread {}", no);

        let rx = rx_orig.clone();
        let results_tx = results_tx_orig.clone();
        let config = config.clone();
        tokio::spawn(async move {
            loop {
                while let Ok(target) = rx.recv().await {

                    /* empty host for a Target means we are asked to quit */
                    if target.host.len() == 0 {
                        log::trace!("Exit requested for Scan Thread {}", no);
                        let _ = results_tx.send(ScanResult::Done).await;
                        break;
                    }

                    let scan_type = scan.scan_type.clone().unwrap();
                    let result = match scan_type {
                        ScanType::Tls => {
                            tls_scan_target(&config, &target).await
                        },
                        ScanType::Ssh => {
                            ssh_scan_target(&config, &target).await
                        }
                    };
                    let _ = results_tx.send(result).await;                    
                }

                log::trace!("Exiting Scan Thread {}", no);
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