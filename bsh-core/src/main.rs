//! BSH CLI — Brockian Secure Hash command-line interface

use std::env;
use std::fs;
use std::io::{self, Read};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Brockian Secure Hash (BSH) v0.1.0");
        eprintln!("Copyright (c) 2026 Christopher Brock / QuantumProof");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  bsh <string>        Hash a string");
        eprintln!("  bsh -f <file>       Hash a file");
        eprintln!("  bsh -               Hash stdin");
        eprintln!("  bsh --test          Run verification tests");
        eprintln!("  bsh --bench         Quick performance benchmark");
        return;
    }

    match args[1].as_str() {
        "--test" => bsh_core::run_tests(),
        "--bench" => bsh_core::run_bench(),
        "-f" => {
            if args.len() < 3 {
                eprintln!("Error: -f requires a filename");
                std::process::exit(1);
            }
            match fs::read(&args[2]) {
                Ok(data) => println!("{}  {}", bsh_core::hash_hex(&data), args[2]),
                Err(e) => { eprintln!("Error: {}", e); std::process::exit(1); }
            }
        }
        "-" => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf).unwrap();
            println!("{}  -", bsh_core::hash_hex(&buf));
        }
        _ => println!("{}  \"{}\"", bsh_core::hash_hex(args[1].as_bytes()), args[1]),
    }
}
