//! QuantumProof CLI — unified command-line tool
//!
//! Commands:
//!   qp hash <string>              Hash a string with BSH
//!   qp hash -f <file>             Hash a file
//!   qp hash -                     Hash stdin
//!   qp hash --test                Run BSH verification tests
//!   qp hash --bench               Quick benchmark
//!   qp keygen                     Generate a random BSH-based key
//!   qp keygen --derive <hex> <ctx> Derive child key
//!   qp keygen --rotate <hex>      Rotate a key
//!   qp scan <path>                Scan for quantum-vulnerable crypto
//!   qp version                    Show version info

use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "hash" => cmd_hash(&args[2..]),
        "keygen" => cmd_keygen(&args[2..]),
        "scan" => cmd_scan(&args[2..]),
        "version" => cmd_version(),
        "--help" | "-h" | "help" => print_usage(),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("QuantumProof CLI v0.1.0");
    eprintln!("Copyright (c) 2026 Christopher Brock / QuantumProof");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  qp hash <string>                Hash a string with BSH");
    eprintln!("  qp hash -f <file>               Hash a file");
    eprintln!("  qp hash -                        Hash stdin");
    eprintln!("  qp hash --test                   Run verification tests");
    eprintln!("  qp hash --bench                  Quick benchmark");
    eprintln!("  qp keygen                        Generate a random key");
    eprintln!("  qp keygen --derive <hex> <ctx>   Derive child key");
    eprintln!("  qp keygen --rotate <hex>         Rotate key");
    eprintln!("  qp scan <path>                   Scan for vulnerable crypto");
    eprintln!("  qp version                       Show version");
}

// ─── HASH ───────────────────────────────────────────────

fn cmd_hash(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: qp hash <string | -f <file> | - | --test | --bench>");
        std::process::exit(1);
    }

    match args[0].as_str() {
        "--test" => bsh_core::run_tests(),
        "--bench" => bsh_core::run_bench(),
        "-f" => {
            if args.len() < 2 {
                eprintln!("Error: -f requires a filename");
                std::process::exit(1);
            }
            match fs::read(&args[1]) {
                Ok(data) => println!("{}  {}", bsh_core::hash_hex(&data), args[1]),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "-" => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf).unwrap();
            println!("{}  -", bsh_core::hash_hex(&buf));
        }
        _ => {
            println!(
                "{}  \"{}\"",
                bsh_core::hash_hex(args[0].as_bytes()),
                args[0]
            );
        }
    }
}

// ─── KEYGEN ─────────────────────────────────────────────

fn cmd_keygen(args: &[String]) {
    if args.is_empty() {
        // Generate random key: hash current time + random-ish data
        let seed = format!(
            "qp-keygen-{}-{:?}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::thread::current().id()
        );
        let key = bsh_core::hash_hex(seed.as_bytes());
        println!("{}", key);
        return;
    }

    match args[0].as_str() {
        "--derive" => {
            if args.len() < 3 {
                eprintln!("Usage: qp keygen --derive <parent-hex> <context>");
                std::process::exit(1);
            }
            let parent = &args[1];
            let context = &args[2];
            let input = format!("{}{}", parent, context);
            let child = bsh_core::hash_hex(input.as_bytes());
            println!("{}", child);
        }
        "--rotate" => {
            if args.len() < 2 {
                eprintln!("Usage: qp keygen --rotate <key-hex>");
                std::process::exit(1);
            }
            let rotated = bsh_core::hash_hex(args[1].as_bytes());
            println!("{}", rotated);
        }
        _ => {
            eprintln!("Unknown keygen option: {}", args[0]);
            std::process::exit(1);
        }
    }
}

// ─── SCAN ───────────────────────────────────────────────

struct Finding {
    file: String,
    line: usize,
    severity: &'static str,
    pattern: String,
    context: String,
}

fn cmd_scan(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: qp scan <path>");
        std::process::exit(1);
    }

    let path = Path::new(&args[0]);
    if !path.exists() {
        eprintln!("Error: path does not exist: {}", args[0]);
        std::process::exit(1);
    }

    let mut findings: Vec<Finding> = Vec::new();
    scan_path(path, &mut findings);

    if findings.is_empty() {
        println!("No quantum-vulnerable cryptographic patterns found.");
        return;
    }

    let critical = findings.iter().filter(|f| f.severity == "HIGH").count();
    let medium = findings.iter().filter(|f| f.severity == "MEDIUM").count();

    println!("QuantumProof Vulnerability Scan");
    println!("═══════════════════════════════");
    println!("Path: {}", args[0]);
    println!("Findings: {} HIGH, {} MEDIUM", critical, medium);
    println!();

    for f in &findings {
        let icon = if f.severity == "HIGH" { "!!" } else { " !" };
        println!(
            "  [{}] {} (line {}): {}",
            icon, f.file, f.line, f.pattern
        );
        println!("       {}", f.context.trim());
        println!();
    }

    println!("Recommendation: Migrate to BSH/QSKI for quantum resistance.");
    println!("Run `qp hash --test` to verify BSH is working correctly.");
}

fn scan_path(path: &Path, findings: &mut Vec<Finding>) {
    if path.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                let name = p.file_name().unwrap_or_default().to_string_lossy();
                // Skip hidden dirs, node_modules, target, .git
                if name.starts_with('.') || name == "node_modules" || name == "target" {
                    continue;
                }
                scan_path(&p, findings);
            }
        }
    } else if path.is_file() {
        scan_file(path, findings);
    }
}

fn scan_file(path: &Path, findings: &mut Vec<Finding>) {
    let ext = path
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();

    // Only scan text source files
    let scannable = [
        "rs", "py", "js", "ts", "tsx", "jsx", "go", "java", "c", "cpp", "h", "hpp", "rb",
        "php", "cs", "swift", "kt", "toml", "yaml", "yml", "json", "xml", "conf", "cfg",
        "ini", "env", "sh", "bash", "zsh",
    ];
    if !scannable.contains(&ext.as_str()) {
        return;
    }

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let patterns: Vec<(&str, &str)> = vec![
        // HIGH severity — quantum-vulnerable
        ("RSA", "HIGH"),
        ("rsa_key", "HIGH"),
        ("RSA-2048", "HIGH"),
        ("RSA-4096", "HIGH"),
        ("ECDSA", "HIGH"),
        ("ECDH", "HIGH"),
        ("P-256", "HIGH"),
        ("P-384", "HIGH"),
        ("diffie_hellman", "HIGH"),
        ("DiffieHellman", "HIGH"),
        ("DSA", "HIGH"),
        ("TLS 1.0", "HIGH"),
        ("TLS 1.1", "HIGH"),
        ("TLSv1.0", "HIGH"),
        ("TLSv1.1", "HIGH"),
        // MEDIUM severity
        ("AES-128", "MEDIUM"),
        ("aes_128", "MEDIUM"),
        ("AES128", "MEDIUM"),
        ("SHA-1", "MEDIUM"),
        ("sha1", "MEDIUM"),
        ("MD5", "MEDIUM"),
        ("md5", "MEDIUM"),
    ];

    let file_str = path.to_string_lossy().to_string();

    for (line_num, line) in content.lines().enumerate() {
        for (pattern, severity) in &patterns {
            // Case-sensitive match to avoid false positives
            if line.contains(pattern) {
                // Skip if it's in a comment about the pattern
                findings.push(Finding {
                    file: file_str.clone(),
                    line: line_num + 1,
                    severity,
                    pattern: pattern.to_string(),
                    context: line.to_string(),
                });
                break; // One finding per line
            }
        }
    }
}

// ─── VERSION ────────────────────────────────────────────

fn cmd_version() {
    println!("QuantumProof CLI v0.1.0");
    println!("BSH Engine: bsh-core v0.1.0 (D5 sponge, 24 rounds, 256-bit)");
    println!("Copyright (c) 2026 Christopher Brock / QuantumProof");
    println!("License: Apache-2.0");
    println!("Repository: https://github.com/primaryhosting/quantumproof-bsh");
}
