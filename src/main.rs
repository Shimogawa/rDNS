extern crate core;

mod rdns;

use crate::rdns::dns::Rdns;
use clap::Parser;
use std::error::Error;

#[derive(Parser)]
struct Cli {
    #[clap(short, long, default_value = "0.0.0.0")]
    host: String,
    #[clap(short, long, default_value_t = 53)]
    port: u16,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let mut d = Rdns::new(&args.host, args.port)?;
    d.start()?;
    Ok(())
}
