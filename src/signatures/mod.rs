//! Signature database loader and matcher.
//!
//! Supports ClamAV .hdb (MD5/SHA256 hash) and .ndb (content pattern) formats.
//! Uses Aho-Corasick for fast multi-pattern matching.

use aho_corasick::AhoCorasick;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// A single malware signature.
#[derive(Debug, Clone)]
pub struct Signature {
    pub name: String,
    pub sig_type: SigType,
}

#[derive(Debug, Clone)]
pub enum SigType {
    /// MD5 hash match
    Md5(String),
    /// SHA256 hash match
    Sha256(String),
    /// Byte pattern match (hex string from .ndb)
    Pattern(Vec<u8>),
}

/// The signature database.
pub struct SigDB {
    /// Hash-based lookups (O(1))
    pub md5_sigs: HashMap<String, String>,    // md5 -> malware name
    pub sha256_sigs: HashMap<String, String>,  // sha256 -> malware name
    /// Pattern-based matching (Aho-Corasick)
    pub pattern_matcher: Option<AhoCorasick>,
    pub pattern_names: Vec<String>,
    /// YARA pattern matcher (separate to avoid rebuilding ndb matcher)
    pub yara_matcher: Option<AhoCorasick>,
    pub yara_start_idx: usize,
    /// Stats
    pub total_sigs: usize,
}

impl SigDB {
    pub fn new() -> Self {
        SigDB {
            md5_sigs: HashMap::new(),
            sha256_sigs: HashMap::new(),
            pattern_matcher: None,
            pattern_names: Vec::new(),
            yara_matcher: None,
            yara_start_idx: 0,
            total_sigs: 0,
        }
    }

    /// Load all signature files from a directory.
    pub fn load_dir(&mut self, dir: &Path) -> std::io::Result<usize> {
        let mut count = 0;
        if !dir.exists() {
            return Ok(0);
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                match path.extension().and_then(|e| e.to_str()) {
                    Some("hdb") | Some("hsb") => count += self.load_hash_file(&path)?,
                    Some("ndb") => count += self.load_ndb_file(&path)?,
                    Some("yar") | Some("yara") => count += self.load_yara_file(&path)?,
                    _ => {}
                }
            }
        }
        self.total_sigs = self.md5_sigs.len() + self.sha256_sigs.len() + self.pattern_names.len();
        Ok(self.total_sigs)
    }

    /// Load ClamAV .hdb/.hsb hash signature file.
    /// Format: hash:size:name
    fn load_hash_file(&mut self, path: &Path) -> std::io::Result<usize> {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() >= 3 {
                let hash = parts[0].to_lowercase();
                let name = parts[2].to_string();
                if hash.len() == 32 {
                    self.md5_sigs.insert(hash, name);
                } else if hash.len() == 64 {
                    self.sha256_sigs.insert(hash, name);
                }
                count += 1;
            }
        }
        Ok(count)
    }

    /// Load ClamAV .ndb content pattern file.
    /// Format: name:target_type:offset:hex_signature
    fn load_ndb_file(&mut self, path: &Path) -> std::io::Result<usize> {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut count = 0;
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(4, ':').collect();
            if parts.len() >= 4 {
                let name = parts[0].to_string();
                let hex_sig = parts[3];
                // Simple hex patterns only (skip wildcards for now)
                if !hex_sig.contains('*') && !hex_sig.contains('{') {
                    if let Some(bytes) = hex_to_bytes(hex_sig) {
                        patterns.push(bytes);
                        self.pattern_names.push(name);
                        count += 1;
                    }
                }
            }
        }
        if !patterns.is_empty() {
            self.pattern_matcher = Some(
                AhoCorasick::builder()
                    .build(&patterns)
                    .expect("Failed to build Aho-Corasick automaton"),
            );
        }
        Ok(count)
    }

    /// Load a YARA rule file — extracts hex strings and ASCII patterns.
    /// This is a lightweight parser that handles common YARA patterns without
    /// the full YARA engine. Supports: hex strings, ASCII text patterns.
    fn load_yara_file(&mut self, path: &Path) -> std::io::Result<usize> {
        let content = fs::read_to_string(path)?;
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut count = 0;
        let mut current_rule = String::new();
        let mut in_strings = false;

        for line in content.lines() {
            let trimmed = line.trim();

            // Track rule name
            if trimmed.starts_with("rule ") {
                if let Some(name) = trimmed
                    .strip_prefix("rule ")
                    .and_then(|s| s.split_whitespace().next())
                {
                    current_rule = name.trim_end_matches('{').trim().to_string();
                }
            }

            if trimmed == "strings:" {
                in_strings = true;
                continue;
            }
            if trimmed == "condition:" || trimmed.starts_with("condition:") {
                in_strings = false;
                continue;
            }

            if in_strings {
                // Parse: $name = { hex hex hex } or $name = "ascii string"
                if let Some(eq_pos) = trimmed.find('=') {
                    let value = trimmed[eq_pos + 1..].trim();

                    if value.starts_with('{') && value.ends_with('}') {
                        // Hex string: { 4D 5A 90 00 }
                        let hex_str: String = value[1..value.len() - 1]
                            .chars()
                            .filter(|c| c.is_ascii_hexdigit())
                            .collect();
                        if !hex_str.is_empty() {
                            if let Some(bytes) = hex_to_bytes(&hex_str) {
                                let rule_name =
                                    format!("YARA:{}", current_rule);
                                patterns.push(bytes);
                                self.pattern_names.push(rule_name);
                                count += 1;
                            }
                        }
                    } else if value.starts_with('"') && value.ends_with('"') {
                        // ASCII string: "malware_string"
                        let ascii = &value[1..value.len() - 1];
                        if ascii.len() >= 4 {
                            let rule_name = format!("YARA:{}", current_rule);
                            patterns.push(ascii.as_bytes().to_vec());
                            self.pattern_names.push(rule_name);
                            count += 1;
                        }
                    }
                }
            }
        }

        if !patterns.is_empty() {
            // Record where YARA names start in pattern_names
            // YARA names were appended after any ndb pattern names
            self.yara_start_idx = self.pattern_names.len() - count;
            let yara_matcher = AhoCorasick::builder()
                .build(&patterns)
                .expect("Failed to build YARA Aho-Corasick automaton");
            self.yara_matcher = Some(yara_matcher);
        }

        Ok(count)
    }

    /// Build the Aho-Corasick matcher after all patterns are loaded.
    pub fn finalize(&mut self) {
        self.total_sigs = self.md5_sigs.len() + self.sha256_sigs.len() + self.pattern_names.len();
    }

    /// Check a file's hashes against the database.
    pub fn check_hash_md5(&self, hash: &str) -> Option<&str> {
        self.md5_sigs.get(hash).map(|s| s.as_str())
    }

    pub fn check_hash_sha256(&self, hash: &str) -> Option<&str> {
        self.sha256_sigs.get(hash).map(|s| s.as_str())
    }

    /// Scan file content for pattern matches (ndb + YARA).
    pub fn scan_content(&self, data: &[u8]) -> Vec<String> {
        let mut hits = Vec::new();
        if let Some(ref matcher) = self.pattern_matcher {
            for mat in matcher.find_iter(data) {
                if let Some(name) = self.pattern_names.get(mat.pattern().as_usize()) {
                    if !hits.contains(name) {
                        hits.push(name.clone());
                    }
                }
            }
        }
        if let Some(ref matcher) = self.yara_matcher {
            for mat in matcher.find_iter(data) {
                let idx = self.yara_start_idx + mat.pattern().as_usize();
                if let Some(name) = self.pattern_names.get(idx) {
                    if !hits.contains(name) {
                        hits.push(name.clone());
                    }
                }
            }
        }
        hits
    }
}

/// Convert a hex string to bytes.
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        match u8::from_str_radix(&hex[i..i + 2], 16) {
            Ok(b) => bytes.push(b),
            Err(_) => return None,
        }
    }
    Some(bytes)
}
