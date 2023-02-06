// #![deny(warnings)]

#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use std::path::Path;
use std::fs::{self, File};
use clap::Parser;
use clap::{Args, Subcommand};
use std::path::PathBuf;
use serde::Serialize;
use fido_mds::FidoMds;
use std::str::FromStr;

use tracing::{debug, info, trace, warn, error};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use webauthn_rs_device_catalog::quirks::Quirks;
use webauthn_rs_device_catalog::device_statements::Mds;

mod enrichment;
mod proto;

#[derive(Debug, Subcommand)]
#[clap(about = "Webauthn RS Device Catalog Generator and Query Tool")]
pub enum Opt {
    /// Given a valid FIDO MDS and the Webauthn RS enrichment data, generate
    /// the Webauthn RS Device Statements.
    GenerateDs {
        #[clap(short, long)]
        debug: bool,
        fido_mds_path: PathBuf,
        enrichment_path: PathBuf,
        output: PathBuf,
    },

    /// Given a valid FIDO MDS and the Webauthn RS enrichment data, generate
    /// the Webauthn RS Device Catalog Static Site Markdown
    GenerateSite {
        #[clap(short, long)]
        debug: bool,
        fido_mds_path: PathBuf,
        enrichment_path: PathBuf,
        output: PathBuf,
    },

    /// Given the Webauthn RS enrichment data, generate the quirks file for
    /// Webauthn Authenticator RS
    GenerateQuirks {
        #[clap(short, long)]
        debug: bool,
        enrichment_path: PathBuf,
        output: PathBuf,
    },

    /// Query the device catalog based on an expression.
    Query {
        #[clap(short, long)]
        debug: bool,
        dcpath: PathBuf,
        expression: String,
    },

    /*
    /// Given the Webauthn RS Device Statements and a Query over the DS, emit the set
    /// of Attestations CA's and Associated AAGUIDS that would satisfy.
    ExportAttestationList {
    }
    */
}

impl Opt {
    fn debug(&self) -> bool {
        match self {
            Opt::GenerateDs { debug, .. }
            | Opt::GenerateSite { debug, .. }
            | Opt::GenerateQuirks { debug, .. }
            | Opt::Query { debug, .. } => *debug,
        }
    }
}

#[derive(Debug, clap::Parser)]
#[clap(about = "Webauthn RS Device Catalog Tool")]
pub struct CliParser {
    #[clap(subcommand)]
    pub commands: Opt,
}

fn read_fido_mds
<P: AsRef<Path> + std::fmt::Debug>
(
    path: P
) -> Result<FidoMds, ()>
    
{
    let s = fs::read_to_string(path)
        .map_err(|e| {
            error!(?e, "FidoMDS file error");
        })?;

    FidoMds::from_str(&s).map_err(|e| {
        error!(?e, "FidoMDS parse error");
    })
}

fn write_output <P: AsRef<Path> + std::fmt::Debug, R: Serialize>
(output: &P, data: &R) {
    let mut output_file = match File::create(output) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to create/open {:?}", output);
            return;
        }
    };

    serde_json::to_writer_pretty(output_file, data)
        .map_err(|e| {
            error!("Failed to output to {:?}", output);
        });
}

fn main() {
    let opt = CliParser::parse();

    let fmt_layer = fmt::layer().with_writer(std::io::stderr);

    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| {
            if opt.commands.debug() {
                EnvFilter::try_new("debug")
            } else {
                EnvFilter::try_new("info")
            }
        })
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    match opt.commands {
        Opt::GenerateDs {
            debug: _,
            fido_mds_path,
            enrichment_path,
            output,
        } => {
            let enrichment_data = match enrichment::Enrichment::new(enrichment_path.as_path()) {
                Ok(e) => e,
                Err(e) => {
                    error!("Failed to open enrichment data {:?}", enrichment_path);
                    return;
                }
            };

            let fido_mds = match read_fido_mds(fido_mds_path.as_path()) {
                Ok(e) => e,
                Err(e) => {
                    error!("Failed to open fido MDS data {:?}", fido_mds_path);
                    return;
                }
            };

            let enriched_mds = match enrichment::EnrichedMds::try_from((&fido_mds, &enrichment_data)) {
                Ok(e) => e,
                Err(e) => {
                    error!("Failed to enrich fido MDS data");
                    return;
                }
            };

            let device_statements: Mds = (&enriched_mds).into();

            write_output(&output, &device_statements);
        }
        Opt::GenerateSite {
            debug: _,
            fido_mds_path,
            enrichment_path,
            output,
        } => {
            todo!()
        }
        Opt::GenerateQuirks {
            debug: _,
            enrichment_path,
            output,
        } => {
            let enrichment_data = match enrichment::Enrichment::new(enrichment_path.as_path()) {
                Ok(e) => e,
                Err(e) => {
                    error!("Failed to open enrichment data {:?}", enrichment_path);
                    return;
                }
            };

            let quirks: Quirks = (&enrichment_data).into();

            write_output(&output, &quirks);
        }
        Opt::Query {
            debug: _,
            dcpath,
            expression,
        } => {
            todo!()
        }
    }
}

