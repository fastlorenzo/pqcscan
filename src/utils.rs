use anyhow::{anyhow, Result};
use std::fmt;
use serde::{Serialize, Deserialize};

pub struct ScanOptions {
    pub num_threads: usize,
    pub targets: Vec<Target>
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Target {
    pub host: String,
    pub port: u16
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

pub fn parse_single_target(input: &String) -> Result<Target> {
    match input.rfind(':') {
        None => {
            Err(anyhow!("Could not find :<PORT> in {input}"))
        },
        Some(pos) => {
            let port = input[pos+1..input.len()].parse::<u16>();
            match port {
                Err(e) => {
                    Err(anyhow!("Invalid port. Value not in range [0-65535]."))
                }
                Ok(port) => {
                    Ok(Target {
                        host: input[..pos].to_string(),
                        port: port
                    })
                }
            }
        }
    }
}
