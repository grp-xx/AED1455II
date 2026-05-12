use clap::{ArgGroup, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(group(
    ArgGroup::new("input")
        .required(true)
        .args(["interface", "file"])
))]
struct Cli {
    /// Network interface to read from
    #[arg(short = 'i', long)]
    interface: Option<String>,

    /// File to read from
    #[arg(short = 'f', long)]
    file: Option<PathBuf>,
    
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() {
    let cli = Cli::parse();

    match (cli.interface, cli.file) {
        (Some(interface), None) => {
            verbose_log(cli.verbose, 2, &format!("Using interface: {interface}")[..]);
            
            let mut cap = pcap::Capture::from_device(&interface[..]).unwrap().open().unwrap();
            while let Ok(packet) = cap.next_packet() {
                let s = format!("Received packet! {:?}", packet);
                verbose_log(cli.verbose, 2, &s);
            }
        }
        (None, Some(file)) => {
            verbose_log(cli.verbose, 2, &format!("Using file: {}", file.display()));
        }
        _ => unreachable!("clap enforces exactly one input source"),
    }


}

fn verbose_log(verbose: u8, verbose_level: u8, message: &str) {
    if verbose >= verbose_level {
        println!("[VERBOSE] {}", message);
    }
}