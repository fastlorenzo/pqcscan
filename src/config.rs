use crate::ssh::SshConfig;

pub struct Config {
    pub ssh_config: SshConfig
}

impl Config {
    pub fn new() -> Config {
        let cfg = Config {
            ssh_config: SshConfig::new()
        };

        return cfg;
    }
}
