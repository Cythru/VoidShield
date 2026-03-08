//! VoidShield — Next-Gen Antivirus Engine
//!
//! Usage:
//!   voidshield scan <path>         Full scan of file or directory
//!   voidshield quick-scan          Scan common malware locations
//!   voidshield realtime            Start real-time protection daemon
//!   voidshield update              Download/update signature databases
//!   voidshield quarantine list     List quarantined files
//!   voidshield quarantine restore  Restore a quarantined file

mod firewall;
mod quarantine;
mod realtime;
mod scanner;
mod signatures;

use clap::{Parser, Subcommand};
use log::{error, info};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

const SIG_DIR: &str = "/var/lib/voidshield/signatures";
const DEFAULT_SIG_DIR: &str = "signatures-db";

#[derive(Parser)]
#[command(name = "voidshield")]
#[command(about = "VoidShield — Next-Gen Antivirus Engine", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file or directory for threats
    Scan {
        /// Path to scan
        path: String,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
    /// Quick scan of common malware locations
    QuickScan {
        #[arg(long)]
        json: bool,
    },
    /// Start real-time filesystem protection
    Realtime {
        /// Paths to monitor (default: /home, /tmp, /var/tmp)
        #[arg(long, num_args = 1..)]
        watch: Option<Vec<String>>,
    },
    /// Update signature databases
    Update,
    /// Manage quarantined files
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },
    /// Show database statistics
    Stats,
    /// Firewall management
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },
}

#[derive(Subcommand)]
enum FirewallAction {
    /// Start the firewall and apply rules
    Start,
    /// Stop the firewall and remove all rules
    Stop,
    /// Show firewall status
    Status,
    /// List all firewall rules
    List,
    /// Block an IP, port, or both
    Block {
        /// IP address or CIDR to block
        #[arg(long)]
        ip: Option<String>,
        /// Port to block
        #[arg(long)]
        port: Option<u16>,
        /// Direction: in, out, both (default: both)
        #[arg(long, default_value = "both")]
        dir: String,
    },
    /// Allow an IP, port, or both
    Allow {
        #[arg(long)]
        ip: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long, default_value = "both")]
        dir: String,
    },
    /// Remove a rule by ID
    Remove {
        /// Rule ID to remove
        id: u32,
    },
}

#[derive(Subcommand)]
enum QuarantineAction {
    /// List all quarantined files
    List,
    /// Restore a file from quarantine
    Restore {
        /// SHA256 hash of the file to restore
        sha256: String,
    },
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let cli = Cli::parse();

    // Load signature database
    let mut db = signatures::SigDB::new();
    let sig_dir = if Path::new(SIG_DIR).exists() {
        PathBuf::from(SIG_DIR)
    } else {
        PathBuf::from(DEFAULT_SIG_DIR)
    };

    let start = Instant::now();
    match db.load_dir(&sig_dir) {
        Ok(count) => {
            info!(
                "Loaded {} signatures in {:.1}ms",
                count,
                start.elapsed().as_millis()
            );
        }
        Err(e) => {
            error!("Failed to load signatures from {:?}: {}", sig_dir, e);
            info!("Run 'voidshield update' to download signature databases");
        }
    }

    match cli.command {
        Commands::Scan { path, json } => cmd_scan(&path, &db, json),
        Commands::QuickScan { json } => cmd_quick_scan(&db, json),
        Commands::Realtime { watch } => cmd_realtime(db, watch),
        Commands::Update => cmd_update(),
        Commands::Quarantine { action } => cmd_quarantine(action),
        Commands::Stats => cmd_stats(&db),
        Commands::Firewall { action } => cmd_firewall(action),
    }
}

fn cmd_firewall(action: FirewallAction) {
    println!("╔══════════════════════════════════════════╗");
    println!("║  VoidShield — Firewall                   ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    match action {
        FirewallAction::Start => firewall::cmd_firewall_start(),
        FirewallAction::Stop => firewall::cmd_firewall_stop(),
        FirewallAction::Status => firewall::cmd_firewall_status(),
        FirewallAction::List => firewall::cmd_firewall_list(),
        FirewallAction::Block { ip, port, dir } => firewall::cmd_firewall_block(ip, port, &dir),
        FirewallAction::Allow { ip, port, dir } => firewall::cmd_firewall_allow(ip, port, &dir),
        FirewallAction::Remove { id } => firewall::cmd_firewall_remove(id),
    }
}

fn cmd_scan(path: &str, db: &signatures::SigDB, json: bool) {
    let path = Path::new(path);
    if !path.exists() {
        eprintln!("Error: path '{}' does not exist", path.display());
        std::process::exit(1);
    }

    let start = Instant::now();
    if !json {
        println!("╔══════════════════════════════════════════╗");
        println!("║     VoidShield — Full Scan Starting      ║");
        println!("╚══════════════════════════════════════════╝");
        println!();
    }

    let results = if path.is_file() {
        vec![scanner::scan_file(path, db)]
    } else {
        scanner::scan_directory(path, db, Some(&|done, total, _file| {
            if done % 100 == 0 || done == total {
                eprint!("\r  Scanning: {}/{} files... ", done, total);
            }
        }))
    };

    let elapsed = start.elapsed();
    eprintln!();

    let total = results.len();
    let clean = results
        .iter()
        .filter(|r| matches!(r.status, scanner::ScanStatus::Clean))
        .count();
    let infected: Vec<_> = results
        .iter()
        .filter(|r| matches!(r.status, scanner::ScanStatus::Infected))
        .collect();
    let errors = results
        .iter()
        .filter(|r| matches!(r.status, scanner::ScanStatus::Error(_)))
        .count();

    if json {
        println!("{}", serde_json::to_string_pretty(&results).unwrap());
        return;
    }

    if !infected.is_empty() {
        println!("⚠  THREATS FOUND:");
        println!("─────────────────────────────────────────────");
        for result in &infected {
            println!("  🔴 {}", result.path);
            for threat in &result.threats {
                println!("     └─ {}", threat);
            }
        }
        println!();
    }

    println!("═══════════════════════════════════════════");
    println!("  Scan Complete");
    println!("───────────────────────────────────────────");
    println!("  Files scanned:  {}", total);
    println!("  Clean:          {}", clean);
    println!("  Infected:       {}", infected.len());
    println!("  Errors:         {}", errors);
    println!("  Time:           {:.2}s", elapsed.as_secs_f64());
    println!(
        "  Speed:          {:.0} files/sec",
        total as f64 / elapsed.as_secs_f64().max(0.001)
    );
    println!("═══════════════════════════════════════════");

    if !infected.is_empty() {
        std::process::exit(1);
    }
}

fn cmd_quick_scan(db: &signatures::SigDB, json: bool) {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home".into());
    let quick_paths = vec![
        format!("{}/Downloads", home),
        "/tmp".into(),
        "/var/tmp".into(),
        format!("{}/.local/bin", home),
    ];

    println!("╔══════════════════════════════════════════╗");
    println!("║     VoidShield — Quick Scan              ║");
    println!("╚══════════════════════════════════════════╝");

    for path in quick_paths {
        if Path::new(&path).exists() {
            println!("\n  Scanning: {}", path);
            cmd_scan(&path, db, json);
        }
    }
}

fn cmd_realtime(db: signatures::SigDB, watch: Option<Vec<String>>) {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home".into());
    let watch_paths = watch.unwrap_or_else(|| {
        vec![home, "/tmp".into(), "/var/tmp".into()]
    });

    println!("╔══════════════════════════════════════════╗");
    println!("║  VoidShield — Real-Time Protection       ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("  Monitoring:");
    for p in &watch_paths {
        println!("    📁 {}", p);
    }
    println!();
    println!("  Press Ctrl+C to stop.");
    println!();

    let db = Arc::new(db);
    match realtime::start_realtime_monitor(db, watch_paths) {
        Ok(_watcher) => {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        Err(e) => {
            eprintln!("Failed to start real-time monitor: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_update() {
    println!("╔══════════════════════════════════════════╗");
    println!("║  VoidShield — Signature Update           ║");
    println!("╚══════════════════════════════════════════╝");
    println!();

    let sig_dir = if Path::new(SIG_DIR).exists() || std::fs::create_dir_all(SIG_DIR).is_ok() {
        PathBuf::from(SIG_DIR)
    } else {
        PathBuf::from(DEFAULT_SIG_DIR)
    };
    std::fs::create_dir_all(&sig_dir).ok();

    let sources = vec![
        ("https://database.clamav.net/main.cvd", "main.cvd", "ClamAV Main DB"),
        ("https://database.clamav.net/daily.cvd", "daily.cvd", "ClamAV Daily DB"),
        ("https://database.clamav.net/bytecode.cvd", "bytecode.cvd", "ClamAV Bytecode DB"),
    ];

    for (url, filename, label) in &sources {
        let dest = sig_dir.join(filename);
        print!("  Downloading {}... ", label);

        match reqwest::blocking::Client::builder()
            .user_agent("VoidShield/0.1")
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .and_then(|c| c.get(*url).send())
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.bytes() {
                        Ok(bytes) => {
                            std::fs::write(&dest, &bytes).ok();
                            println!("OK ({:.1} MB)", bytes.len() as f64 / 1024.0 / 1024.0);
                        }
                        Err(e) => println!("FAILED (read: {})", e),
                    }
                } else {
                    println!("FAILED (HTTP {})", resp.status());
                }
            }
            Err(e) => println!("FAILED ({})", e),
        }
    }

    println!();
    println!("  Signatures saved to: {}", sig_dir.display());
}

fn cmd_quarantine(action: QuarantineAction) {
    match action {
        QuarantineAction::List => {
            let manifest = quarantine::QuarantineManifest::load();
            if manifest.entries.is_empty() {
                println!("  No files in quarantine.");
                return;
            }
            println!("  Quarantined files:");
            println!("  ─────────────────────────────────────────");
            for entry in &manifest.entries {
                println!("  🔒 {}", entry.original_path);
                println!("     SHA256: {}", entry.sha256);
                println!("     Threats: {:?}", entry.threats);
                println!("     Date: {}", entry.quarantined_at);
                println!();
            }
        }
        QuarantineAction::Restore { sha256 } => {
            let mut manifest = quarantine::QuarantineManifest::load();
            match manifest.restore_file(&sha256) {
                Ok(true) => println!("  File restored successfully."),
                Ok(false) => println!("  File not found in quarantine."),
                Err(e) => eprintln!("  Error restoring file: {}", e),
            }
        }
    }
}

fn cmd_stats(db: &signatures::SigDB) {
    println!("╔══════════════════════════════════════════╗");
    println!("║  VoidShield — Database Statistics        ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("  Total signatures:    {}", db.total_sigs);
    println!("  MD5 hash sigs:       {}", db.md5_sigs.len());
    println!("  SHA256 hash sigs:    {}", db.sha256_sigs.len());
    println!("  Pattern sigs:        {}", db.pattern_names.len());

    let manifest = quarantine::QuarantineManifest::load();
    println!("  Quarantined files:   {}", manifest.entries.len());
}
