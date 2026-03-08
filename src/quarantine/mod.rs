//! Quarantine vault — safely isolates infected files.
//!
//! Files are moved to a quarantine directory, renamed with their SHA256,
//! and their original metadata is stored in a manifest.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const QUARANTINE_DIR: &str = "/var/lib/voidshield/quarantine";
const MANIFEST_FILE: &str = "/var/lib/voidshield/quarantine/manifest.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub original_path: String,
    pub quarantine_name: String,
    pub threats: Vec<String>,
    pub quarantined_at: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct QuarantineManifest {
    pub entries: Vec<QuarantineEntry>,
}

impl QuarantineManifest {
    pub fn load() -> Self {
        match fs::read_to_string(MANIFEST_FILE) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        fs::create_dir_all(QUARANTINE_DIR)?;
        fs::write(MANIFEST_FILE, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn quarantine_file(
        &mut self,
        path: &Path,
        threats: Vec<String>,
        sha256: &str,
    ) -> std::io::Result<()> {
        fs::create_dir_all(QUARANTINE_DIR)?;

        let quarantine_name = format!("{}.quarantined", sha256);
        let dest = PathBuf::from(QUARANTINE_DIR).join(&quarantine_name);

        let size = fs::metadata(path)?.len();

        // Move file to quarantine
        fs::rename(path, &dest)?;

        self.entries.push(QuarantineEntry {
            original_path: path.display().to_string(),
            quarantine_name,
            threats,
            quarantined_at: chrono::Utc::now().to_rfc3339(),
            size,
            sha256: sha256.to_string(),
        });

        self.save()?;
        Ok(())
    }

    pub fn restore_file(&mut self, sha256: &str) -> std::io::Result<bool> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.sha256 == sha256);

        if let Some(idx) = idx {
            let entry = &self.entries[idx];
            let src = PathBuf::from(QUARANTINE_DIR).join(&entry.quarantine_name);
            let dest = PathBuf::from(&entry.original_path);

            if src.exists() {
                // Ensure parent dir exists
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::rename(src, dest)?;
            }
            self.entries.remove(idx);
            self.save()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
