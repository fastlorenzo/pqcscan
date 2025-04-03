use anyhow::{anyhow, Result};
use std::fmt;
use serde::{Serialize, Deserialize};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::Duration;
use std::net::{SocketAddr, ToSocketAddrs};

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

pub async fn socket_create_and_connect(target: &Target, timeout: u64) -> Result<(SocketAddr, TcpStream)> {

    let addrs_resolved = format!("{0}:{1}", target.host, target.port).to_socket_addrs();
    if addrs_resolved.is_err() {
        log::trace!("Could not resolve {target}: {:?}", addrs_resolved.err());
        return Err(anyhow!("Could not resolve {}", target.host));
    }

    let addr = addrs_resolved.unwrap().next();
    if addr.is_none() {
        return Err(anyhow!("Could not resolve {}", target.host));
    }

    let addr = addr.unwrap();
    log::trace!("Resolved {0} to {1}", target, addr);

    let socket = match addr {
        SocketAddr::V4(_) => {
            TcpSocket::new_v4().unwrap()
        }
        SocketAddr::V6(_) => {
            TcpSocket::new_v6().unwrap()
        }
    };

    let connect = socket.connect(addr);
    match tokio::time::timeout(Duration::from_secs(timeout), connect).await {
        Ok(Ok(e)) => {
            Ok((addr, e))
        },
        Ok(Err(e)) => {
            Err(anyhow!("Could not connect to {addr}"))
        }
        Err(_) => {
            let err = format!("Timed out after {timeout}s connecting to {addr}");
            log::debug!("{}", err);
            Err(anyhow!(err))
        }
    }
}