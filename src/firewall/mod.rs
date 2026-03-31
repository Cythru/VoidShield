//! VoidShield Firewall Module
//!
//! Application-layer firewall with IP/port blocking, connection logging,
//! and rate limiting. Uses iptables/nftables under the hood for kernel-level
//! packet filtering.

use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

// System config dir (Linux system install); user fallback used on macOS/Android/Windows
const SYSTEM_CONFIG_DIR: &str = "/var/lib/voidshield";
const USER_CONFIG_DIR: &str = ".local/share/voidshield";

fn config_dir() -> PathBuf {
    let sys = Path::new(SYSTEM_CONFIG_DIR);
    if sys.exists() || cfg!(target_os = "linux") && !cfg!(target_os = "android") {
        return sys.to_path_buf();
    }
    // macOS / Android / Windows: use ~/.local/share/voidshield
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(USER_CONFIG_DIR))
        .unwrap_or_else(|_| PathBuf::from("voidshield-data"))
}
const CHAIN_NAME: &str = "VOIDSHIELD";

// ── Rule types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Action {
    Block,
    Allow,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: u32,
    pub name: String,
    pub direction: Direction,
    pub action: Action,
    pub protocol: Protocol,
    pub ip: Option<String>,       // IP or CIDR (e.g. "192.168.1.0/24")
    pub port: Option<u16>,
    pub port_range: Option<(u16, u16)>,
    pub enabled: bool,
    #[serde(default)]
    pub hit_count: u64,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub max_connections: u32,
    pub window_secs: u64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    pub enabled: bool,
    pub default_inbound: Action,
    pub default_outbound: Action,
    pub rules: Vec<FirewallRule>,
    pub rate_limits: Vec<RateLimitRule>,
    pub log_connections: bool,
    pub log_file: String,
    next_id: u32,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_inbound: Action::Allow,
            default_outbound: Action::Allow,
            rules: vec![
                // Default rules: block known bad ports
                FirewallRule {
                    id: 1,
                    name: "Block Telnet inbound".into(),
                    direction: Direction::Inbound,
                    action: Action::Block,
                    protocol: Protocol::Tcp,
                    ip: None,
                    port: Some(23),
                    port_range: None,
                    enabled: true,
                    hit_count: 0,
                    created_at: now_string(),
                },
                FirewallRule {
                    id: 2,
                    name: "Block SMB inbound".into(),
                    direction: Direction::Inbound,
                    action: Action::Block,
                    protocol: Protocol::Tcp,
                    ip: None,
                    port: Some(445),
                    port_range: None,
                    enabled: true,
                    hit_count: 0,
                    created_at: now_string(),
                },
                FirewallRule {
                    id: 3,
                    name: "Block RDP inbound".into(),
                    direction: Direction::Inbound,
                    action: Action::Block,
                    protocol: Protocol::Tcp,
                    ip: None,
                    port: Some(3389),
                    port_range: None,
                    enabled: true,
                    hit_count: 0,
                    created_at: now_string(),
                },
            ],
            rate_limits: vec![RateLimitRule {
                ip: None,
                port: None,
                max_connections: 100,
                window_secs: 60,
                enabled: true,
            }],
            log_connections: true,
            log_file: "firewall.log".into(),
            next_id: 4,
        }
    }
}

// ── Connection tracker (rate limiting) ───────────────────────────────────────

struct ConnectionTracker {
    counts: HashMap<String, Vec<Instant>>,
}

impl ConnectionTracker {
    fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    fn record(&mut self, key: &str, window: Duration) -> u32 {
        let now = Instant::now();
        let entries = self.counts.entry(key.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) < window);
        entries.push(now);
        entries.len() as u32
    }
}

// ── Config I/O ───────────────────────────────────────────────────────────────

fn config_path() -> PathBuf {
    if Path::new(CONFIG_DIR).exists() {
        PathBuf::from(CONFIG_DIR).join("firewall.json")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let dir = PathBuf::from(&home).join(USER_CONFIG_DIR);
        fs::create_dir_all(&dir).ok();
        dir.join("firewall.json")
    }
}

fn log_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let dir = PathBuf::from(&home).join(USER_CONFIG_DIR);
    fs::create_dir_all(&dir).ok();
    dir.join("firewall.log")
}

fn now_string() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl FirewallConfig {
    pub fn load() -> Self {
        let path = config_path();
        if path.exists() {
            match fs::read_to_string(&path) {
                Ok(data) => match serde_json::from_str(&data) {
                    Ok(cfg) => return cfg,
                    Err(e) => warn!("Bad firewall config, using defaults: {}", e),
                },
                Err(e) => warn!("Can't read firewall config: {}", e),
            }
        }
        let cfg = Self::default();
        cfg.save();
        cfg
    }

    pub fn save(&self) {
        let path = config_path();
        if let Ok(data) = serde_json::to_string_pretty(self) {
            if let Err(e) = fs::write(&path, data) {
                error!("Failed to save firewall config: {}", e);
            }
        }
    }

    pub fn add_rule(&mut self, mut rule: FirewallRule) -> u32 {
        rule.id = self.next_id;
        rule.created_at = now_string();
        self.next_id += 1;
        let id = rule.id;
        self.rules.push(rule);
        self.save();
        id
    }

    pub fn remove_rule(&mut self, id: u32) -> bool {
        let len = self.rules.len();
        self.rules.retain(|r| r.id != id);
        if self.rules.len() < len {
            self.save();
            true
        } else {
            false
        }
    }

    pub fn toggle_rule(&mut self, id: u32) -> Option<bool> {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == id) {
            rule.enabled = !rule.enabled;
            let state = rule.enabled;
            self.save();
            Some(state)
        } else {
            None
        }
    }
}

// ── iptables backend ─────────────────────────────────────────────────────────

fn has_iptables() -> bool {
    Command::new("iptables")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn has_nft() -> bool {
    Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn iptables_run(args: &[&str]) -> Result<String, String> {
    let out = Command::new("sudo")
        .arg("iptables")
        .args(args)
        .output()
        .map_err(|e| format!("iptables exec failed: {}", e))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).to_string())
    }
}

fn ensure_chain() -> Result<(), String> {
    // Create VOIDSHIELD chain if it doesn't exist
    let _ = iptables_run(&["-N", CHAIN_NAME]);
    // Ensure INPUT jumps to our chain
    let check = iptables_run(&["-C", "INPUT", "-j", CHAIN_NAME]);
    if check.is_err() {
        iptables_run(&["-I", "INPUT", "1", "-j", CHAIN_NAME])?;
    }
    // Ensure OUTPUT jumps to our chain
    let check = iptables_run(&["-C", "OUTPUT", "-j", CHAIN_NAME]);
    if check.is_err() {
        iptables_run(&["-I", "OUTPUT", "1", "-j", CHAIN_NAME])?;
    }
    Ok(())
}

fn flush_chain() -> Result<(), String> {
    iptables_run(&["-F", CHAIN_NAME])?;
    Ok(())
}

fn protocol_str(p: &Protocol) -> &str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Icmp => "icmp",
        Protocol::All => "all",
    }
}

fn apply_rule(rule: &FirewallRule) -> Result<(), String> {
    if !rule.enabled {
        return Ok(());
    }

    let action_str = match rule.action {
        Action::Block => "DROP",
        Action::Allow => "ACCEPT",
        Action::Log => "LOG",
    };

    let chains = match rule.direction {
        Direction::Inbound => vec![("INPUT", "-s", "-d")],
        Direction::Outbound => vec![("OUTPUT", "-d", "-s")],
        Direction::Both => vec![("INPUT", "-s", "-d"), ("OUTPUT", "-d", "-s")],
    };

    for (_chain_hint, src_flag, _dst_flag) in &chains {
        let mut args: Vec<String> = vec![
            "-A".into(),
            CHAIN_NAME.into(),
        ];

        // Protocol
        if rule.protocol != Protocol::All {
            args.push("-p".into());
            args.push(protocol_str(&rule.protocol).into());
        }

        // IP filter
        if let Some(ref ip) = rule.ip {
            // For inbound: match source; for outbound: match destination
            args.push(src_flag.to_string());
            args.push(ip.clone());
        }

        // Port filter
        if let Some(port) = rule.port {
            if rule.protocol == Protocol::Tcp || rule.protocol == Protocol::Udp {
                args.push("--dport".into());
                args.push(port.to_string());
            }
        }

        // Port range
        if let Some((start, end)) = rule.port_range {
            if rule.protocol == Protocol::Tcp || rule.protocol == Protocol::Udp {
                args.push("--dport".into());
                args.push(format!("{}:{}", start, end));
            }
        }

        // Action
        args.push("-j".into());
        args.push(action_str.into());

        // Comment
        args.push("-m".into());
        args.push("comment".into());
        args.push("--comment".into());
        args.push(format!("voidshield:{}", rule.id));

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        iptables_run(&arg_refs)?;
    }

    Ok(())
}

fn apply_rate_limit(rl: &RateLimitRule) -> Result<(), String> {
    if !rl.enabled {
        return Ok(());
    }

    let mut args: Vec<String> = vec![
        "-A".into(),
        CHAIN_NAME.into(),
        "-p".into(),
        "tcp".into(),
    ];

    if let Some(ref ip) = rl.ip {
        args.push("-s".into());
        args.push(ip.clone());
    }

    if let Some(port) = rl.port {
        args.push("--dport".into());
        args.push(port.to_string());
    }

    // Use connlimit for rate limiting
    args.extend([
        "-m".into(),
        "connlimit".into(),
        "--connlimit-above".into(),
        rl.max_connections.to_string(),
        "-j".into(),
        "DROP".into(),
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        "voidshield:ratelimit".into(),
    ]);

    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    iptables_run(&arg_refs)?;
    Ok(())
}

// ── Public API ───────────────────────────────────────────────────────────────

pub fn apply_config(config: &FirewallConfig) -> Result<(), String> {
    if !config.enabled {
        info!("Firewall disabled in config");
        return Ok(());
    }

    if !has_iptables() {
        return Err("iptables not found — install iptables to use the firewall".into());
    }

    ensure_chain()?;
    flush_chain()?;

    let mut applied = 0;
    let mut errors = 0;

    for rule in &config.rules {
        if !rule.enabled {
            continue;
        }
        match apply_rule(rule) {
            Ok(()) => {
                applied += 1;
                info!("Applied rule {}: {} ({})", rule.id, rule.name,
                      match rule.action { Action::Block => "BLOCK", Action::Allow => "ALLOW", Action::Log => "LOG" });
            }
            Err(e) => {
                errors += 1;
                error!("Failed to apply rule {}: {}", rule.id, e);
            }
        }
    }

    for rl in &config.rate_limits {
        if let Err(e) = apply_rate_limit(rl) {
            error!("Failed to apply rate limit: {}", e);
            errors += 1;
        } else {
            applied += 1;
        }
    }

    info!("Firewall applied: {} rules ({} errors)", applied, errors);
    Ok(())
}

pub fn stop() -> Result<(), String> {
    if !has_iptables() {
        return Ok(());
    }
    // Flush our chain
    let _ = flush_chain();
    // Remove jumps from INPUT/OUTPUT
    let _ = iptables_run(&["-D", "INPUT", "-j", CHAIN_NAME]);
    let _ = iptables_run(&["-D", "OUTPUT", "-j", CHAIN_NAME]);
    // Delete the chain
    let _ = iptables_run(&["-X", CHAIN_NAME]);
    info!("Firewall stopped — all VoidShield rules removed");
    Ok(())
}

pub fn status() -> FirewallStatus {
    let config = FirewallConfig::load();
    let chain_exists = iptables_run(&["-L", CHAIN_NAME, "-n", "--line-numbers"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    let active_rules = if chain_exists {
        iptables_run(&["-L", CHAIN_NAME, "-n", "--line-numbers"])
            .unwrap_or_default()
            .lines()
            .filter(|l| l.starts_with(|c: char| c.is_ascii_digit()))
            .count()
    } else {
        0
    };

    FirewallStatus {
        enabled: config.enabled,
        active: chain_exists,
        total_rules: config.rules.len(),
        active_rules,
        rate_limits: config.rate_limits.len(),
        default_inbound: format!("{:?}", config.default_inbound),
        default_outbound: format!("{:?}", config.default_outbound),
    }
}

#[derive(Debug)]
pub struct FirewallStatus {
    pub enabled: bool,
    pub active: bool,
    pub total_rules: usize,
    pub active_rules: usize,
    pub rate_limits: usize,
    pub default_inbound: String,
    pub default_outbound: String,
}

pub fn log_connection(src: &str, dst: &str, port: u16, action: &str) {
    let path = log_path();
    let entry = format!(
        "{} | {} -> {}:{} | {}\n",
        now_string(),
        src,
        dst,
        port,
        action
    );
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        use std::io::Write;
        let _ = f.write_all(entry.as_bytes());
    }
}

// ── CLI helpers ──────────────────────────────────────────────────────────────

pub fn cmd_firewall_start() {
    println!("  Starting VoidShield Firewall...");
    let config = FirewallConfig::load();
    match apply_config(&config) {
        Ok(()) => {
            println!("  Firewall active with {} rules", config.rules.iter().filter(|r| r.enabled).count());
            println!("  Rate limits: {}", config.rate_limits.iter().filter(|r| r.enabled).count());
            println!("  Config: {}", config_path().display());
        }
        Err(e) => {
            eprintln!("  Failed to start firewall: {}", e);
            eprintln!("  (requires sudo / root for iptables)");
        }
    }
}

pub fn cmd_firewall_stop() {
    println!("  Stopping VoidShield Firewall...");
    match stop() {
        Ok(()) => println!("  Firewall stopped."),
        Err(e) => eprintln!("  Error: {}", e),
    }
}

pub fn cmd_firewall_status() {
    let st = status();
    println!("  Firewall enabled:     {}", st.enabled);
    println!("  Chain active:         {}", st.active);
    println!("  Configured rules:     {}", st.total_rules);
    println!("  Active iptables rules: {}", st.active_rules);
    println!("  Rate limit rules:     {}", st.rate_limits);
    println!("  Default inbound:      {}", st.default_inbound);
    println!("  Default outbound:     {}", st.default_outbound);
}

pub fn cmd_firewall_list() {
    let config = FirewallConfig::load();
    if config.rules.is_empty() {
        println!("  No firewall rules configured.");
        return;
    }
    println!("  ID  | Enabled | Direction | Action | Protocol | Target          | Name");
    println!("  ----+---------+-----------+--------+----------+-----------------+--------------------");
    for r in &config.rules {
        let target = match (&r.ip, r.port, r.port_range) {
            (Some(ip), Some(p), _) => format!("{}:{}", ip, p),
            (Some(ip), None, _) => ip.clone(),
            (None, Some(p), _) => format!("*:{}", p),
            (None, None, Some((a, b))) => format!("*:{}-{}", a, b),
            _ => "*".into(),
        };
        println!(
            "  {:<3} | {:<7} | {:<9} | {:<6} | {:<8} | {:<15} | {}",
            r.id,
            if r.enabled { "yes" } else { "no" },
            format!("{:?}", r.direction),
            format!("{:?}", r.action),
            format!("{:?}", r.protocol),
            target,
            r.name
        );
    }
}

pub fn cmd_firewall_block(ip: Option<String>, port: Option<u16>, direction: &str) {
    let mut config = FirewallConfig::load();
    let dir = match direction {
        "in" | "inbound" => Direction::Inbound,
        "out" | "outbound" => Direction::Outbound,
        _ => Direction::Both,
    };
    let name = match (&ip, port) {
        (Some(i), Some(p)) => format!("Block {}:{}", i, p),
        (Some(i), None) => format!("Block {}", i),
        (None, Some(p)) => format!("Block port {}", p),
        _ => "Block all".into(),
    };
    let rule = FirewallRule {
        id: 0,
        name,
        direction: dir,
        action: Action::Block,
        protocol: if port.is_some() { Protocol::Tcp } else { Protocol::All },
        ip,
        port,
        port_range: None,
        enabled: true,
        hit_count: 0,
        created_at: String::new(),
    };
    let id = config.add_rule(rule);
    println!("  Added block rule #{}", id);

    // Apply immediately if firewall is active
    if config.enabled {
        if let Err(e) = apply_config(&config) {
            eprintln!("  Warning: rule saved but couldn't apply: {}", e);
        } else {
            println!("  Rule applied.");
        }
    }
}

pub fn cmd_firewall_allow(ip: Option<String>, port: Option<u16>, direction: &str) {
    let mut config = FirewallConfig::load();
    let dir = match direction {
        "in" | "inbound" => Direction::Inbound,
        "out" | "outbound" => Direction::Outbound,
        _ => Direction::Both,
    };
    let name = match (&ip, port) {
        (Some(i), Some(p)) => format!("Allow {}:{}", i, p),
        (Some(i), None) => format!("Allow {}", i),
        (None, Some(p)) => format!("Allow port {}", p),
        _ => "Allow all".into(),
    };
    let rule = FirewallRule {
        id: 0,
        name,
        direction: dir,
        action: Action::Allow,
        protocol: if port.is_some() { Protocol::Tcp } else { Protocol::All },
        ip,
        port,
        port_range: None,
        enabled: true,
        hit_count: 0,
        created_at: String::new(),
    };
    let id = config.add_rule(rule);
    println!("  Added allow rule #{}", id);

    if config.enabled {
        if let Err(e) = apply_config(&config) {
            eprintln!("  Warning: rule saved but couldn't apply: {}", e);
        } else {
            println!("  Rule applied.");
        }
    }
}

pub fn cmd_firewall_remove(id: u32) {
    let mut config = FirewallConfig::load();
    if config.remove_rule(id) {
        println!("  Removed rule #{}", id);
        if config.enabled {
            let _ = apply_config(&config);
        }
    } else {
        eprintln!("  Rule #{} not found", id);
    }
}
