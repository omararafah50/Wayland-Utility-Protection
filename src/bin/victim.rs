use libc::{prctl, PR_SET_DUMPABLE};
use std::env;
use std::io::{self, Write};
use std::process;
use std::thread::sleep;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("A");

    // Known secret signature to search for in memory dumps
    let secret_key: [u8; 32] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
        0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
    ];

    match mode {
        "A" => {
            println!("[Condition A: Monolithic] Running PID: {}", process::id());
            println!("Secret allocated at address: {:p}", &secret_key);
            io::stdout().flush().unwrap();
            sleep(Duration::from_secs(60));
        }
        "B" => {
            println!("[Condition B: Distributed / Unprotected] Parent PID: {}", process::id());
            unsafe {
                let pid = libc::fork();
                if pid == 0 {
                    // Child process holding 1 share
                    println!("Child Worker PID: {}", process::id());
                    println!("Share allocated at address: {:p}", &secret_key);
                    io::stdout().flush().unwrap();
                    sleep(Duration::from_secs(60));
                    process::exit(0);
                }
            }
            sleep(Duration::from_secs(65));
        }
        "C" => {
            println!("[Condition C: Kernel Isolated] Parent PID: {}", process::id());
            unsafe {
                let pid = libc::fork();
                if pid == 0 {
                    // Lock down child memory via prctl
                    if prctl(PR_SET_DUMPABLE, 0) != 0 {
                        eprintln!("Failed to set PR_SET_DUMPABLE");
                    }
                    println!("Child Worker PID: {} (PR_SET_DUMPABLE = 0)", process::id());
                    println!("Share allocated at address: {:p}", &secret_key);
                    io::stdout().flush().unwrap();
                    sleep(Duration::from_secs(60));
                    process::exit(0);
                }
            }
            sleep(Duration::from_secs(65));
        }
        _ => eprintln!("Unknown mode. Use A, B, or C."),
    }
}
