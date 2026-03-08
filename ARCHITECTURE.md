# VoidShield — Next-Gen Antivirus Engine

## Architecture: C++ / Rust / Zig hybrid

### Language Split
- **Rust** — Core engine, signature matching, file scanner, process monitor. Memory-safe by default.
- **C++** — ML/heuristic engine, YARA rule integration, PE/ELF parser. Mature ecosystem.
- **Zig** — Kernel module (eBPF on Linux), real-time filesystem hooks, ultra-low-latency syscall interception.

### Module Map

```
VoidShield/
├── core/              (Rust) — Main engine, orchestration, config
│   ├── scanner/       — File scanner (signature + heuristic)
│   ├── signatures/    — Signature DB loader (ClamAV-compatible + custom)
│   ├── quarantine/    — Quarantine vault (encrypted storage)
│   ├── updater/       — Signature auto-update daemon
│   └── ipc/           — IPC for GUI/CLI communication
├── heuristics/        (C++) — ML-based detection
│   ├── static/        — Static analysis (entropy, imports, sections)
│   ├── behavioral/    — Behavioral analysis (API call patterns)
│   ├── yara/          — YARA rule engine integration
│   └── ml_model/      — TinyML classifier (ONNX runtime)
├── realtime/          (Zig) — Real-time protection
│   ├── ebpf/          — eBPF programs for syscall monitoring
│   ├── fanotify/      — Linux fanotify filesystem monitor
│   ├── inotify/       — Fallback inotify watcher
│   └── netfilter/     — Network packet inspection hooks
├── cli/               (Rust) — Command-line interface
├── gui/               (Rust + egui) — Desktop GUI
├── daemon/            (Rust) — Background service
└── signatures-db/     — Signature database files
```

### Detection Layers (matching Bitdefender/Kaspersky)

1. **Signature Matching** — Fast multi-pattern matching (Aho-Corasick)
   - ClamAV signature format compatibility (free 10M+ sigs)
   - Custom VoidShield signature format (more compact)
   - YARA rules support

2. **Heuristic Engine** — Static analysis
   - PE/ELF/Mach-O header anomaly detection
   - Import table analysis (suspicious API combos)
   - Entropy analysis (packed/encrypted sections)
   - String extraction + pattern matching

3. **ML Classification** — Lightweight neural net
   - Feature extraction from binary structure
   - ONNX model (~5MB) trained on malware corpus
   - Gradient-boosted trees for fast pre-filter

4. **Behavioral Analysis** — Runtime monitoring
   - eBPF syscall tracing (file, network, process)
   - API call sequence matching against known patterns
   - Ransomware canary files (honeypot detection)
   - Process injection detection

5. **Network Protection**
   - DNS-over-HTTPS with blocklist
   - Connection reputation scoring
   - Phishing URL detection
   - C2 beacon pattern detection

6. **Real-Time File Protection**
   - fanotify pre-content hooks (scan before open)
   - On-access scanning with caching (don't re-scan clean files)
   - Memory-mapped scanning for speed

### Performance Targets
- Full scan: 100GB in <10 minutes
- On-access latency: <5ms per file decision
- Memory: <150MB resident
- Signature load: <2 seconds for 10M sigs
- Zero false positives on system files

### Startup Integration
- systemd service: `voidshield.service`
- Starts at boot, runs as root for fanotify access
- CLI/GUI connect via Unix socket IPC
