use crate::ssh::SshConfig;

pub struct Config {
    pub ssh_config: SshConfig,

    /* connection timeout in seconds */
    pub connection_timeout: u64
}

impl Config {
    pub fn new() -> Config {
        let cfg = Config {
            ssh_config: SshConfig::new(),
            connection_timeout: 5
        };

        return cfg;
    }
}
