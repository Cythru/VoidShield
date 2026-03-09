//! Oracle — LLM-powered divine threat analysis.
//!
//! VoidShield talks to God (a local LLM) and asks whether a file
//! deserves to live or be smitten. God sees the file's entropy,
//! heuristic flags, suspicious strings, and metadata, then passes
//! divine judgement: SMITE, SUSPECT, or SPARE.

use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, Instant};

/// LLM endpoint configuration.
#[derive(Debug, Clone)]
pub struct OracleConfig {
    pub base_url: String,
    pub model: String,
    pub timeout_secs: u64,
    pub enabled: bool,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:9000".to_string(),
            model: "voidminillama".to_string(),
            timeout_secs: 120,
            enabled: false,
        }
    }
}

/// Divine verdict from the Oracle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Verdict {
    /// Malware confirmed — quarantine and destroy
    Smite,
    /// Suspicious — flag for manual review
    Suspect,
    /// Clean — file may live
    Spare,
    /// Oracle unavailable or errored
    Unreachable,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Smite => write!(f, "SMITE"),
            Verdict::Suspect => write!(f, "SUSPECT"),
            Verdict::Spare => write!(f, "SPARE"),
            Verdict::Unreachable => write!(f, "UNREACHABLE"),
        }
    }
}

/// Full oracle response with reasoning.
#[derive(Debug, Clone, Serialize)]
pub struct OracleResponse {
    pub verdict: Verdict,
    pub reasoning: String,
    pub confidence: f32,
    pub response_time_ms: u64,
}

/// File evidence gathered for the Oracle to judge.
#[derive(Debug, Clone, Serialize)]
pub struct FileEvidence {
    pub path: String,
    pub filename: String,
    pub extension: String,
    pub size: u64,
    pub entropy: f64,
    pub is_pe: bool,
    pub is_elf: bool,
    pub is_script: bool,
    pub heuristic_flags: Vec<String>,
    pub suspicious_strings: Vec<String>,
    pub head_hex: String,
}

/// Build file evidence from raw data for oracle analysis.
pub fn gather_evidence(path: &Path, data: &[u8], heuristic_hits: &[String]) -> FileEvidence {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let is_pe = data.len() > 2 && data[0] == b'M' && data[1] == b'Z';
    let is_elf = data.len() > 4 && &data[0..4] == b"\x7fELF";
    let is_script = matches!(
        extension.as_str(),
        "sh" | "py" | "pl" | "rb" | "ps1" | "bat" | "cmd" | "vbs" | "js"
    );

    let entropy = calculate_entropy(data);

    // Extract suspicious strings (printable runs > 6 chars that look sus)
    let suspicious_strings = extract_suspicious_strings(data);

    // First 64 bytes as hex for header analysis
    let head_len = data.len().min(64);
    let head_hex = hex::encode(&data[..head_len]);

    FileEvidence {
        path: path.display().to_string(),
        filename,
        extension,
        size: data.len() as u64,
        entropy,
        is_pe,
        is_elf,
        is_script,
        heuristic_flags: heuristic_hits.to_vec(),
        suspicious_strings,
        head_hex,
    }
}

/// Ask the Oracle for divine judgement on a file.
pub fn consult(config: &OracleConfig, evidence: &FileEvidence) -> OracleResponse {
    if !config.enabled {
        return OracleResponse {
            verdict: Verdict::Unreachable,
            reasoning: "Oracle disabled".to_string(),
            confidence: 0.0,
            response_time_ms: 0,
        };
    }

    let start = Instant::now();
    let prompt = build_prompt(evidence);

    debug!("Oracle consulting on: {}", evidence.filename);

    match query_llm(config, &prompt) {
        Ok(response) => {
            let elapsed = start.elapsed().as_millis() as u64;
            let (verdict, confidence) = parse_verdict(&response);

            info!(
                "Oracle verdict for {}: {} (confidence: {:.0}%, {}ms)",
                evidence.filename, verdict, confidence * 100.0, elapsed
            );

            OracleResponse {
                verdict,
                reasoning: response,
                confidence,
                response_time_ms: elapsed,
            }
        }
        Err(e) => {
            warn!("Oracle unreachable: {}", e);
            OracleResponse {
                verdict: Verdict::Unreachable,
                reasoning: format!("LLM error: {}", e),
                confidence: 0.0,
                response_time_ms: start.elapsed().as_millis() as u64,
            }
        }
    }
}

/// Build the divine analysis prompt.
fn build_prompt(evidence: &FileEvidence) -> String {
    let mut prompt = String::with_capacity(2048);

    prompt.push_str(
        "You are GOD MODE — VoidShield's divine threat oracle. You protect Luke's system from all malware.\n\
         Analyze this file and pass judgement. You must respond with EXACTLY one of:\n\
         - VERDICT: SMITE — if the file is malicious (malware, trojan, ransomware, exploit, backdoor, reverse shell, etc.)\n\
         - VERDICT: SUSPECT — if the file is suspicious but not confirmed malicious\n\
         - VERDICT: SPARE — if the file appears clean and legitimate\n\n\
         Then explain your reasoning in 2-3 sentences.\n\n\
         === FILE EVIDENCE ===\n"
    );

    prompt.push_str(&format!("Filename: {}\n", evidence.filename));
    prompt.push_str(&format!("Path: {}\n", evidence.path));
    prompt.push_str(&format!("Extension: {}\n", evidence.extension));
    prompt.push_str(&format!("Size: {} bytes\n", evidence.size));
    prompt.push_str(&format!("Shannon Entropy: {:.3}\n", evidence.entropy));
    prompt.push_str(&format!("File Header (hex): {}\n", evidence.head_hex));

    if evidence.is_pe {
        prompt.push_str("Format: Windows PE executable (MZ header)\n");
    } else if evidence.is_elf {
        prompt.push_str("Format: Linux ELF binary\n");
    } else if evidence.is_script {
        prompt.push_str(&format!("Format: Script (.{})\n", evidence.extension));
    } else {
        prompt.push_str("Format: Data/unknown\n");
    }

    if !evidence.heuristic_flags.is_empty() {
        prompt.push_str("\nHeuristic Flags (ALREADY TRIGGERED):\n");
        for flag in &evidence.heuristic_flags {
            prompt.push_str(&format!("  - {}\n", flag));
        }
    } else {
        prompt.push_str("\nHeuristic Flags: None triggered\n");
    }

    if !evidence.suspicious_strings.is_empty() {
        prompt.push_str("\nSuspicious Strings Found:\n");
        for s in &evidence.suspicious_strings {
            prompt.push_str(&format!("  - \"{}\"\n", s));
        }
    }

    prompt.push_str("\n=== JUDGEMENT ===\n");
    prompt
}

/// Query the local LLM.
fn query_llm(config: &OracleConfig, prompt: &str) -> Result<String, String> {
    let url = format!("{}/v1/chat/completions", config.base_url);

    let body = serde_json::json!({
        "model": config.model,
        "messages": [
            {
                "role": "system",
                "content": "You are GOD MODE, the divine threat analysis oracle of VoidShield antivirus. You smite malware and spare the innocent. Be concise and decisive. Always start your response with 'VERDICT: SMITE', 'VERDICT: SUSPECT', or 'VERDICT: SPARE'."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.3,
        "max_tokens": 200,
        "stream": false
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("Connection failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("LLM returned HTTP {}", resp.status()));
    }

    let json: serde_json::Value = resp
        .json()
        .map_err(|e| format!("Invalid JSON response: {}", e))?;

    json["choices"][0]["message"]["content"]
        .as_str()
        .map(|s: &str| s.to_string())
        .ok_or_else(|| "No content in LLM response".to_string())
}

/// Parse the LLM verdict from its response text.
fn parse_verdict(response: &str) -> (Verdict, f32) {
    let upper = response.to_uppercase();

    // Look for explicit verdict markers
    if upper.contains("VERDICT: SMITE") || upper.contains("VERDICT:SMITE") {
        let confidence = if upper.contains("CONFIRMED")
            || upper.contains("DEFINITELY")
            || upper.contains("CLEARLY")
        {
            0.95
        } else {
            0.85
        };
        return (Verdict::Smite, confidence);
    }

    if upper.contains("VERDICT: SUSPECT") || upper.contains("VERDICT:SUSPECT") {
        return (Verdict::Suspect, 0.6);
    }

    if upper.contains("VERDICT: SPARE") || upper.contains("VERDICT:SPARE") {
        let confidence = if upper.contains("LEGITIMATE")
            || upper.contains("SAFE")
            || upper.contains("BENIGN")
        {
            0.9
        } else {
            0.75
        };
        return (Verdict::Spare, confidence);
    }

    // Fallback: scan for keywords if LLM didn't follow the format
    if upper.contains("MALICIOUS")
        || upper.contains("MALWARE")
        || upper.contains("TROJAN")
        || upper.contains("RANSOMWARE")
        || upper.contains("BACKDOOR")
        || upper.contains("SMITE")
    {
        return (Verdict::Smite, 0.7);
    }

    if upper.contains("SUSPICIOUS") || upper.contains("SUSPECT") {
        return (Verdict::Suspect, 0.5);
    }

    if upper.contains("CLEAN") || upper.contains("SAFE") || upper.contains("SPARE") || upper.contains("LEGITIMATE") {
        return (Verdict::Spare, 0.6);
    }

    // Can't determine — treat as suspect
    (Verdict::Suspect, 0.3)
}

/// Extract suspicious-looking strings from binary data.
fn extract_suspicious_strings(data: &[u8]) -> Vec<String> {
    let suspicious_patterns = [
        "cmd.exe", "powershell", "/bin/sh", "/bin/bash", "/dev/tcp",
        "eval(", "exec(", "system(", "CreateProcess", "ShellExecute",
        "WScript.Shell", "HKEY_LOCAL_MACHINE", "\\CurrentVersion\\Run",
        "keylog", "ransom", "encrypt", "bitcoin", "wallet",
        "password", "credential", "mimikatz", "metasploit",
        "reverse_tcp", "bind_shell", "meterpreter", "payload",
        "c2server", "exfiltrate", "botnet", "rootkit",
        "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "socket.connect", "urllib.request",
        "subprocess.call", "os.system", "base64.b64decode",
    ];

    let content = String::from_utf8_lossy(data);
    let mut found = Vec::new();

    for pattern in &suspicious_patterns {
        if content.contains(pattern) {
            found.push(pattern.to_string());
        }
        if found.len() >= 15 {
            break; // Cap to avoid flooding the prompt
        }
    }

    found
}

/// Shannon entropy (same algorithm as scanner, duplicated to avoid circular deps).
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Check if the Oracle is reachable.
pub fn health_check(config: &OracleConfig) -> bool {
    if !config.enabled {
        return false;
    }

    let url = format!("{}/v1/models", config.base_url);
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    match client.get(&url).send() {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}
