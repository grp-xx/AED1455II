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

    println!("Default Device: {}", pcap::Device::lookup().unwrap().unwrap().name);

    match (cli.interface, cli.file) {
        (Some(interface), None) => {
            verbose_log(cli.verbose, 2, &format!("Using interface: {interface}")[..]);
            
            let mut cap = pcap::Capture::from_device(&interface[..])
                                                            .unwrap()
                                                            .promisc(true)
                                                            .immediate_mode(true)
                                                            .timeout(1000)
                                                            .open()
                                                            .unwrap();
//            while let Ok(packet) = cap.next_packet() {
//                let s = format!("Received frame with EtherType! {:?}", &packet.data[12..14]);
//                verbose_log(cli.verbose, 2, &s);
//            }
            cap.filter("ip", true).unwrap();
//            let handler = |packet: pcap::Packet<'_>| { 
//                let s = format!("Received frame with EtherType! {:?}", &packet.data[12..14]);
//                verbose_log(cli.verbose, 2, &s);
//            };

            cap.for_each(Some(10), handler).unwrap();
            println!("Packet RX: {}", cap.stats().unwrap().received);
            println!("Packet dropped: {}", cap.stats().unwrap().dropped);
            println!("Packet dropped by interface: {}", cap.stats().unwrap().if_dropped);
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

fn handler(packet: pcap::Packet<'_>) {
    let s = format!("Received frame with EtherType! {:?}", &packet.data[12..14]);
    println!("{}", s);
}