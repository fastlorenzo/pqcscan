use crate::Target;
use serde::{Serialize, Deserialize};
use chrono::prelude::*;

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
    Done
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Scan {
    pub results: Vec<ScanResult>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>
}
