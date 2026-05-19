use clap::Parser;
use std::path::PathBuf;


#[derive(Parser, Debug)]

struct Cli {
    /// Network interface to read from
    #[arg(short = 'i', long)]
    interface: Option<String>,

    /// File to read from
    #[arg(short = 'f', long)]
    file: Option<PathBuf>,

    /// Packet rate in packets per second
    #[arg(short = 'r', long, default_value = None)]
    rate: Option<u32>,

    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}
fn main() {
    let cli = Cli::parse();

    let mut cap = pcap::Capture::from_file(cli.file.unwrap()).unwrap();

    let mut tx = pcap::Capture::from_device(&cli.interface.unwrap()[..]).unwrap()
                                                            .promisc(true)   
                                                            .immediate_mode(true)
                                                            .open()
                                                            .unwrap();

    let mut t_old = if let Ok(packet) = cap.next_packet() {
        verbose_log(cli.verbose, 1, &format!("First packet timestamp: {}.{}", packet.header.ts.tv_sec, packet.header.ts.tv_usec)[..]);
        tx.sendpacket(packet.data).unwrap();
        packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0
    } else {0.0};


    while let Ok(packet) = cap.next_packet() {
        let sleeptime = if let Some(rate) = cli.rate {
                                  1.0 / (rate as f64)
                        } else {
                            (packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0) - t_old
                        };
        verbose_log(cli.verbose, 2, &format!("Sleeping for: {}", sleeptime)[..]);
        std::thread::sleep(std::time::Duration::from_secs_f64(sleeptime));
        verbose_log(cli.verbose, 3, &format!("Replaying packet with length: {}", packet.header.len)[..]);
        tx.sendpacket(packet.data).unwrap();   
        t_old += sleeptime;
    }

    

}

fn verbose_log(verbose: u8, verbose_level: u8, message: &str) {
    if verbose >= verbose_level {
        println!("[VERBOSE] {}", message);
    }
}