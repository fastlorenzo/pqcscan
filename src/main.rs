use anyhow::{anyhow, Result};
use env_logger::Env;
use clap::{Arg, Command, ArgAction, ArgMatches};
use std::path::PathBuf;
use std::io::{BufReader, BufRead, BufWriter};
use std::fs::File;
use tokio::runtime::Runtime;
use std::sync::Arc;
use rust_embed::RustEmbed;
use tera::{Tera, Context};

mod config;
mod utils;
mod ssh;
mod result;

use crate::utils::{ScanOptions, Target, parse_single_target};
use crate::config::Config;
use crate::ssh::ssh_scan;

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/support"]
#[include = "template.html"]
struct EmbeddedResources;

fn output_args() -> Vec<clap::Arg> {
    vec![
        Arg::new("append")
            .short('a')
            .long("append")
            .help("Append results to output JSON file")
            .action(ArgAction::SetTrue),
        Arg::new("output")
            .short('o')
            .value_name("FILE")
            .long("output")
            .help("JSON file to output results into")
            .action(ArgAction::Set),
    ]
}

fn target_args() -> Vec<clap::Arg> {
    vec![
        Arg::new("target")
            .short('t')
            .long("target")
            .value_name("HOST:PORT")
            .help("HOST:PORT")
            .conflicts_with("target-list")
            .action(ArgAction::Set),
        Arg::new("target-list")
            .short('T')
            .value_name("FILE")
            .long("target-list")
            .help("File listing HOST:PORT entries")
            .conflicts_with("target")
            .action(ArgAction::Set)
            .value_parser(clap::value_parser!(PathBuf)),
    ]
}

fn get_targets(matches: &ArgMatches) -> Result<Vec<Target>> {
    match matches.get_one::<String>("target") {
        Some(t) => {
            Ok(vec![parse_single_target(t)?])
        },
        None => {
            let f = matches.get_one::<PathBuf>("target-list");
            if f.is_none() {
                return Err(anyhow!("specify -t or -T"));
            }
            let file = File::open(f.unwrap())?;
            let reader = BufReader::new(file);
            let mut line_no = 1;
            let mut targets: Vec<Target> = Vec::new();

            for line in reader.lines() {
                let line = line?;

                /* ignore comment lines starting with # */
                let first = line.chars().next().unwrap();
                if first == '#' {
                    continue;
                }

                match parse_single_target(&line) {
                    Ok(t) => {
                        targets.push(t)
                    },
                    Err(e) => {
                        return Err(anyhow!("Parsing HOST:PORT at line {line_no} failed. {e}"));
                    }
                }
                line_no += 1;
            }
            Ok(targets)
        }
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let matches = Command::new("pqcscan")
        .version("1.0")
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .about("Post-Quantum Cryptography Scanner")
        .flatten_help(true)

        .subcommand(
            Command::new("ssh-scan")
                .about("Scan SSH servers")
                .next_help_heading("Target")
                .args(target_args())
                .next_help_heading("Output")
                .args(output_args())
                .disable_help_flag(true)
                .disable_version_flag(true)
        )
        /*
        .subcommand(
            Command::new("tls-scan")
                .about("Scan TLS servers")
                .next_help_heading("Target")
                .args(target_args())
                .next_help_heading("Output")
                .args(output_args())
                .disable_help_flag(true)
                .disable_version_flag(true)
        )
        */
        .subcommand(
            Command::new("report")
                .about("Convert JSON output to HTML report")
                .next_help_heading("Input")
                .next_help_heading("Output")
                .disable_help_flag(true)
                .disable_version_flag(true)
        )
        .get_matches();

    let config = Config::new();

    let mut scan = ScanOptions {
        num_threads: 2,
        targets: vec![]
    };

    match matches.subcommand() {
        Some(("tls-scan", sub_matches)) => {
            let _ = get_targets(sub_matches)?;
            return Err(anyhow!("not implemented yet"));
        },
        Some(("ssh-scan", sub_matches)) => {
            let targets = get_targets(sub_matches)?;
            scan.targets = targets;
            let rt = Runtime::new()?;
            let results = rt.block_on(ssh_scan(Arc::new(config), scan));

            let mut writer = BufWriter::new(std::io::stdout());
            serde_json::to_writer(&mut writer, &results)?;

            let mut tera = Tera::default();
            let html_file = EmbeddedResources::get("template.html").unwrap();
            let html_data = std::str::from_utf8(html_file.data.as_ref())?;
            tera.add_raw_template("template.html", html_data)?;
            let mut ctx = Context::from_serialize(&results)?;
            ctx.insert("title", "wut");

            println!("{}", tera.render("template.html", &ctx)?);
        },
        Some(("report", sub_matches)) => {
        }
        _ => unreachable!("somehow reached this")
    }

    Ok(())
}
