# VoidShield — Next Features Implementation Plan

Date: 2026-03-09

## Current State Summary

The Rust core is fully operational with:
- `src/scanner/mod.rs` — File scanner with hash (MD5/SHA256) and Aho-Corasick pattern matching, basic heuristics (entropy, suspicious PE imports, ELF packing, script threats, reverse shell detection)
- `src/signatures/mod.rs` — SigDB with ClamAV .hdb/.hsb/.ndb loading, YARA rule parser
- `src/realtime/mod.rs` — inotify-based filesystem watcher (via `notify` crate) with auto-quarantine
- `src/quarantine/mod.rs` — Move-and-manifest quarantine vault
- `src/firewall/mod.rs` — iptables-backed IP/port blocking with rate limiting, connection logging
- `src/main.rs` — CLI with scan, quick-scan, realtime, update, quarantine, stats, firewall commands

The `heuristics/` directory exists but is empty — ready for the C++ module.

---

## Feature 1: C++ Heuristics Module

### Purpose

The current Rust heuristic scanner (`scanner::heuristic_scan`) does basic entropy checks and string-matching for suspicious imports. A dedicated C++ module will add deep static analysis of binary formats (PE, ELF, Mach-O) using mature C++ libraries, giving detection capabilities that would be painful to reimplement in pure Rust.

### What It Should Detect

#### 1.1 PE (Portable Executable) Deep Analysis
- **Section anomalies:** Executable sections with write permission (W+X), sections with names like `.UPX0`, `.aspack`, `.nsp0` indicating known packers, sections with zero raw size but large virtual size (hollow sections), entry point outside `.text` section
- **Import table red flags:** Combinations of `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` (process injection trinity), `NtUnmapViewOfSection` (process hollowing), `SetWindowsHookEx` (keylogger), `CryptEncrypt` + file enumeration APIs (ransomware), `InternetOpenUrl` + `CreateFile` (dropper behaviour)
- **Resource anomalies:** Embedded PE files inside resources, encrypted/compressed resources with high entropy, resources larger than the rest of the binary
- **Overlay detection:** Data appended after the PE ends (common in droppers that carry payloads)
- **Timestamp anomalies:** Compilation timestamp in the future, or set to epoch zero
- **Digital signature validation:** Check Authenticode signature presence and validity
- **TLS callback detection:** TLS callbacks are used by malware for anti-debug

#### 1.2 ELF Deep Analysis
- **Section anomalies:** Missing `.text` section, executable `.data` or `.bss`, stripped symbol tables on non-release binaries, unusual interpreter paths (not `/lib64/ld-linux-x86-64.so.2`)
- **Dynamic linking red flags:** `dlopen`/`dlsym` of suspicious libraries, `ptrace` imports (anti-debug or injection), `memfd_create` (fileless execution), `execve` + `socket` combos (reverse shell)
- **Packer detection:** Known packer signatures (UPX magic, MPRESS headers), abnormally high entropy in `.text`
- **GOT/PLT hooking indicators:** Modified GOT entries pointing outside loaded segments

#### 1.3 Mach-O Analysis
- **Fat binary inspection:** Check all architectures for suspicious code
- **Entitlement abuse:** `com.apple.security.cs.disable-library-validation`, `com.apple.security.cs.allow-dyld-environment-variables`
- **Dylib injection vectors:** `LC_LOAD_DYLIB` referencing temp paths, `@rpath` abuse

#### 1.4 Universal Heuristics
- **Entropy profiling:** Per-section entropy analysis (not just whole-file), entropy histogram to detect encrypted payloads hidden in specific sections
- **String analysis:** Suspicious URL patterns (Pastebin/Discord webhook/Telegram bot API URLs), Base64-encoded PE/ELF headers, IP addresses with non-RFC1918 ranges, cryptocurrency wallet address patterns (BTC, ETH, XMR)
- **Opcode analysis:** NOP sled detection, shellcode patterns (common x86/x64 shellcode prologues like `\x31\xc0\x50\x68`), ROP gadget chain indicators

### Integration via FFI

#### Directory Structure
```
heuristics/
├── CMakeLists.txt
├── include/
│   └── voidshield_heuristics.h    # C-compatible FFI header
├── src/
│   ├── heuristics_ffi.cpp         # FFI entry points (extern "C")
│   ├── pe_analyzer.cpp            # PE format analysis
│   ├── pe_analyzer.h
│   ├── elf_analyzer.cpp           # ELF format analysis
│   ├── elf_analyzer.h
│   ├── macho_analyzer.cpp         # Mach-O analysis
│   ├── macho_analyzer.h
│   ├── entropy.cpp                # Per-section entropy engine
│   ├── entropy.h
│   ├── string_extractor.cpp       # Suspicious string extraction
│   ├── string_extractor.h
│   ├── opcode_scanner.cpp         # Shellcode/ROP detection
│   └── opcode_scanner.h
└── tests/
    ├── test_pe.cpp
    └── test_elf.cpp
```

#### FFI Interface Design

The C header (`voidshield_heuristics.h`) exposes a simple, flat C API:

```c
// Opaque handle — C++ internals hidden from Rust
typedef struct VsHeuristicEngine VsHeuristicEngine;

// Lifecycle
VsHeuristicEngine* vs_heuristic_create(void);
void vs_heuristic_destroy(VsHeuristicEngine* engine);

// Analysis — takes raw file bytes, returns JSON result string
// Caller must free the returned string with vs_free_string()
const char* vs_analyze_buffer(VsHeuristicEngine* engine,
                              const uint8_t* data, size_t len,
                              const char* filename);
void vs_free_string(const char* str);

// Individual analyzers (for targeted use)
int vs_get_threat_score(VsHeuristicEngine* engine,
                        const uint8_t* data, size_t len);
// Returns 0-100; >70 = suspicious, >90 = likely malicious
```

The JSON return from `vs_analyze_buffer` contains:
```json
{
  "threat_score": 85,
  "detections": [
    {"type": "PE.SuspiciousImports.ProcessInjection", "severity": "high", "detail": "VirtualAllocEx+WriteProcessMemory+CreateRemoteThread"},
    {"type": "PE.Section.WritableExecutable", "severity": "medium", "detail": ".text has W+X permissions"},
    {"type": "Entropy.PackedSection", "severity": "medium", "detail": ".rsrc entropy 7.92/8.0"}
  ],
  "format": "PE32+",
  "packer": "UPX 3.96"
}
```

#### Rust-Side Integration

In `Cargo.toml`, add:
```toml
[build-dependencies]
cc = "1"      # or cmake = "0.1" if using CMakeLists.txt
```

Create `build.rs`:
- Compile the C++ sources using the `cc` crate (simpler) or invoke cmake
- Link the resulting static library

Create `src/heuristics_ffi.rs`:
- `extern "C"` declarations matching the header
- Safe Rust wrapper: `HeuristicEngine` struct implementing `Drop` for `vs_heuristic_destroy`
- `analyze()` method that calls `vs_analyze_buffer`, converts the JSON string to `serde_json::Value`, then frees it

Modify `scanner::heuristic_scan()`:
- After the current basic checks, if the C++ engine is available, call `engine.analyze(data, path)` and merge the returned detections into the threats vector
- The C++ engine is created once at startup and passed through to the scanner (add it to `SigDB` or create a separate `HeuristicEngine` arc)

#### C++ Dependencies (vendored or system)
- **LIEF** (https://lief-project.github.io/) — Best-in-class PE/ELF/Mach-O parser, BSD licensed, header-only option available
- **Capstone** (http://www.capstone-engine.org/) — Disassembly engine for opcode analysis, BSD licensed
- No other external deps needed; entropy/string analysis is self-contained

#### Build Integration
- `CMakeLists.txt` builds `libvoidshield_heuristics.a` (static library)
- `build.rs` invokes cmake, links the static lib
- CI: install LIEF and Capstone dev packages, then `cargo build` handles the rest

---

## Feature 2: Network Protection

### Purpose

The current firewall module (`firewall/mod.rs`) handles IP/port blocking via iptables rules. Network protection goes deeper: inspecting actual packet content, detecting C2 beacons, blocking phishing/malicious domains, and monitoring for data exfiltration.

### What to Monitor

#### 2.1 DNS Protection
- **Malicious domain blocking:** Maintain a blocklist of known malicious domains (sources: abuse.ch URLhaus, PhishTank, OpenPhish, Disconnect.me malware list, SANS ISC suspicious domains)
- **DNS-over-HTTPS (DoH) enforcement:** Proxy DNS through DoH to prevent DNS poisoning; block plaintext DNS to external resolvers (except the configured DoH upstream)
- **DGA detection:** Domain Generation Algorithm detection — flag domains with high entropy, unusual length distributions, or consonant/vowel ratio anomalies (e.g., `xkjf7829skdj.com`)
- **DNS tunneling detection:** Abnormally long subdomain labels, high query volume to a single domain, TXT record abuse

#### 2.2 Connection Monitoring
- **Reputation scoring:** On each outbound connection, check the destination IP/domain against threat intelligence feeds. Score: known-good (allow), unknown (log), known-bad (block+alert)
- **Geo-IP flagging:** Flag connections to high-risk countries (configurable list) — not auto-block, but log and raise alert
- **Unusual port usage:** Flag outbound connections on non-standard ports (e.g., HTTP traffic on port 8443, SSH on port 4444)
- **Connection frequency anomalies:** Detect port scanning (many connections to sequential ports), brute force (many connections to same port from same source)

#### 2.3 C2 Beacon Detection
- **Periodic callback detection:** Track outbound connection timing — flag regular intervals (e.g., exact 60s, 300s heartbeats) to the same destination, with jitter tolerance
- **Known C2 protocol signatures:** Cobalt Strike beacon profile patterns, Metasploit handler patterns, common RAT communication patterns (njRAT, AsyncRAT, DarkComet HTTP headers)
- **HTTP anomalies:** Suspicious User-Agent strings, HTTP requests with no referer to non-CDN IPs, POST requests with encoded/encrypted bodies to uncommon endpoints
- **Certificate anomalies:** Self-signed certs on HTTPS connections, recently issued certs (<7 days), certs with suspicious Subject/Issuer fields

#### 2.4 Data Exfiltration Detection
- **Volume monitoring:** Alert on large outbound data transfers (configurable threshold, e.g., >100MB to a single IP in 1 hour)
- **Protocol anomalies:** DNS responses much larger than queries (DNS exfiltration), ICMP packets with payload data (ICMP tunneling)
- **Sensitive data patterns:** Credit card regex, SSN patterns, private key headers — in outbound unencrypted traffic only

### Implementation Approach

#### Architecture
```
src/
├── network/
│   ├── mod.rs              # Module root, NetworkProtection struct
│   ├── dns_proxy.rs        # DNS interception + DoH forwarding
│   ├── domain_blocklist.rs # Blocklist loading/matching (trie-based)
│   ├── dga_detector.rs     # DGA heuristics (entropy, n-gram analysis)
│   ├── connection_tracker.rs # Per-connection state tracking
│   ├── reputation.rs       # IP/domain reputation lookup + caching
│   ├── beacon_detector.rs  # C2 beacon timing analysis
│   ├── exfil_detector.rs   # Exfiltration pattern detection
│   └── packet_inspector.rs # Raw packet inspection (AF_PACKET or nfqueue)
```

#### Packet Inspection Strategy

There are three viable approaches on Linux, in order of preference:

**Option A: NFQUEUE (recommended)**
- Use `iptables -j NFQUEUE --queue-num N` to divert packets to userspace
- Rust reads packets from the netfilter queue, inspects them, then returns a verdict (ACCEPT/DROP)
- Crate: `nfqueue` or raw `libnfnetlink` FFI
- Pros: Works with existing iptables integration, can modify packets, synchronous verdict (block before delivery)
- Cons: Requires root, adds latency to every inspected packet

**Option B: AF_PACKET (recommended for passive monitoring)**
- Open a raw socket with `AF_PACKET` to sniff traffic
- Purely passive — observe and alert, cannot block inline
- Crate: `pnet` (provides cross-platform packet parsing) or `afpacket`
- Pros: Zero latency impact, no iptables dependency, works alongside other firewalls
- Cons: Cannot block packets (must pair with iptables rules for blocking)

**Option C: eBPF XDP (future — Zig module)**
- Fastest possible path, runs in kernel, but save this for the Zig eBPF module later
- Network protection module should be designed so the eBPF module can replace the packet inspection layer without changing the analysis logic

**Recommended hybrid approach:** Use AF_PACKET (`pnet` crate) for passive packet capture and analysis. When a threat is detected, dynamically add iptables rules via the existing firewall module to block the offending IP/port. This keeps the network monitor zero-latency for normal traffic while still providing active protection.

#### DNS Proxy Implementation
- Bind a local DNS resolver on 127.0.0.53:53 (or configurable port)
- Intercept DNS queries, check against blocklist (trie or hashset)
- Forward allowed queries via DoH to Cloudflare (1.1.1.1) or Quad9 (9.9.9.9)
- Return NXDOMAIN or 0.0.0.0 for blocked domains
- Configure system DNS to point to VoidShield's resolver (`/etc/resolv.conf` or NetworkManager)
- Crate: `trust-dns-resolver` for DoH, `trust-dns-server` for the local listener

#### Blocklist Format and Sources
- Download lists on `voidshield update`:
  - abuse.ch URLhaus: `https://urlhaus.abuse.ch/downloads/hostfile/`
  - PhishTank: `http://data.phishtank.com/data/online-valid.json`
  - Disconnect.me malware: `https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt`
  - SANS ISC: `https://isc.sans.edu/feeds/suspiciousdomains_High.txt`
- Store as sorted text files in `signatures-db/` (or `/var/lib/voidshield/`)
- Load into a HashSet at startup (typically 100K-500K domains, ~50MB RAM)

#### Rust Crate Dependencies
```toml
pnet = "0.35"                    # Packet capture and parsing
trust-dns-resolver = "0.24"      # DoH client
trust-dns-server = "0.24"        # Local DNS listener
maxminddb = "0.24"               # GeoIP lookups (optional)
```

#### Integration with Existing Code
- Add `Commands::Network { action: NetworkAction }` to the CLI enum in `main.rs`
- Subcommands: `start`, `stop`, `status`, `block-domain <domain>`, `query-reputation <ip>`
- The network monitor runs as a long-lived tokio task alongside the realtime file monitor
- Detected threats are logged to a separate `network.log` and optionally trigger firewall rules via `firewall::FirewallConfig::add_rule()`

#### New CLI Commands
```
voidshield network start         # Start DNS proxy + packet monitor
voidshield network stop          # Stop network protection
voidshield network status        # Show connection stats, blocked domains count
voidshield network block-domain  # Manually add domain to blocklist
voidshield network connections   # Show active connections with reputation scores
```

---

## Feature 3: ML Classifier

### Purpose

Static signatures and heuristic rules are reactive — they detect known patterns. An ML classifier provides probabilistic detection of novel/unknown malware by learning structural features that distinguish malicious from benign binaries, catching zero-day threats that bypass signature matching.

### Model Architecture

#### 3.1 Two-Stage Pipeline

**Stage 1: Gradient-Boosted Decision Tree (GBDT) — Fast Pre-Filter**
- Model: LightGBM or XGBoost, exported to ONNX
- Size: ~500KB-2MB
- Inference time: <1ms per file
- Purpose: Quickly classify 95%+ of files as obviously clean or obviously malicious, only passing ambiguous files (score 30-70) to the neural net
- This is the critical stage — it runs on every scanned file

**Stage 2: Small Neural Network — Deep Analysis**
- Architecture: 1D-CNN or small Transformer on raw byte sequences
- Model: 3-5 convolutional layers with batch norm, global average pooling, 2 FC layers
- Input: First 2MB of the file (zero-padded if shorter), as a sequence of bytes (uint8 values)
- Size: ~5-15MB in ONNX format
- Inference time: 5-50ms per file (CPU)
- Purpose: Catch sophisticated malware that the GBDT misses

Using a two-stage approach keeps overall performance high: the GBDT eliminates 95% of files in <1ms, and only the uncertain 5% hit the neural net.

#### 3.2 Feature Engineering (for GBDT)

Extract these features from each binary before feeding to the GBDT:

**File-level features (15 features):**
1. File size (log-scaled)
2. Whole-file entropy
3. Byte histogram distribution (256 bins, normalized) — compressed to 8 features via PCA or just use: mean, stddev, skewness, kurtosis of the byte frequency distribution
4. Number of printable ASCII strings (length > 4)
5. Average string length
6. Ratio of null bytes to total size

**PE-specific features (20 features, zero for non-PE):**
1. Number of sections
2. Average section entropy
3. Max section entropy
4. Number of sections with W+X permissions
5. Entry point section index
6. Entry point entropy (256 bytes around EP)
7. Number of imported DLLs
8. Number of imported functions
9. Has `VirtualAlloc` import (bool)
10. Has `WriteProcessMemory` import (bool)
11. Has `CreateRemoteThread` import (bool)
12. Has `CryptEncrypt` import (bool)
13. Has network APIs (bool)
14. Has registry APIs (bool)
15. Resource section entropy
16. Overlay size (bytes after PE end)
17. Timestamp age (seconds from compile to now)
18. Has debug info (bool)
19. Has digital signature (bool)
20. Import hash (imphash) — categorical, encoded as hash bucket

**ELF-specific features (10 features, zero for non-ELF):**
1. Number of sections
2. Number of program headers
3. Has `.symtab` (bool)
4. Is stripped (bool)
5. Number of dynamic symbols
6. Has `ptrace` in dynamic symbols (bool)
7. Has `dlopen` in dynamic symbols (bool)
8. Has `execve` in dynamic symbols (bool)
9. Has `socket` in dynamic symbols (bool)
10. Interpreter path hash (categorical bucket)

**Total: ~45 features** — well within GBDT sweet spot.

### Training Data Sources

#### 3.3 Malware Samples (Positive Class)
- **VirusTotal Academic API** — Academic access provides bulk download of labeled samples. Requires affiliation/application.
- **MalwareBazaar (abuse.ch)** — Free, community-driven malware repository. ~1M+ samples with family labels. API: `https://bazaar.abuse.ch/api/`
- **VirusShare** — Large corpus (~48M samples), requires registration. `https://virusshare.com/`
- **TheZoo** — Curated collection of live malware for research. `https://github.com/ytisf/theZoo`
- **EMBER dataset** — Pre-extracted features from 1.1M PE files (600K malicious, 500K benign). Perfect for GBDT training without needing raw samples. `https://github.com/elastic/ember`
- **SOREL-20M** — Sophos 20M sample dataset with labels and features. Largest public malware ML dataset.
- **Practical target:** Start with EMBER (pre-extracted features, trains GBDT immediately) and MalwareBazaar (raw samples for CNN training). Aim for 500K+ malicious samples.

#### 3.4 Benign Samples (Negative Class)
- **System binaries:** `/usr/bin/`, `/usr/lib/` from clean installs of Ubuntu, Fedora, Arch, Windows
- **Package managers:** Download top 10K packages from apt/pacman/chocolatey, extract all binaries
- **EMBER dataset:** Already includes labeled benign PE samples
- **Software installers:** Chrome, Firefox, LibreOffice, Python, Node.js, Steam, etc. — popular legitimate software
- **Practical target:** At least 1:1 ratio with malicious samples, ideally 2:1 benign to reduce false positives. 500K-1M benign samples.

#### 3.5 Training Pipeline
1. Feature extraction script (Rust or Python) processes all samples, outputs feature CSV + labels
2. GBDT training: Python with `lightgbm` or `xgboost`, hyperparameter tuning with cross-validation
3. CNN training: Python with PyTorch, train on raw bytes (first 2MB) of PE/ELF files
4. Export both models to ONNX format
5. Validate on held-out test set: target >99% detection rate with <0.1% false positive rate
6. Store trained ONNX models in `signatures-db/models/` or `/var/lib/voidshield/models/`

### Integration Approach

#### 3.6 Runtime Integration

**ONNX Runtime:**
- Use `ort` crate (Rust bindings for ONNX Runtime) — mature, supports CPU inference, small footprint
- Add to `Cargo.toml`: `ort = "2"` (or `onnxruntime` crate)
- ONNX Runtime shared library (~30MB) ships with the binary or is installed as a system dep

**Module structure:**
```
src/
├── ml/
│   ├── mod.rs              # MlClassifier struct, two-stage pipeline
│   ├── feature_extractor.rs # Extract 45 features from binary data
│   ├── gbdt_model.rs       # GBDT ONNX model wrapper
│   └── cnn_model.rs        # CNN ONNX model wrapper
```

**MlClassifier API:**
```rust
pub struct MlClassifier {
    gbdt: ort::Session,        // Fast pre-filter
    cnn: Option<ort::Session>, // Deep analysis (optional, may not ship initially)
    threshold_gbdt: f32,       // Default: 0.5
    threshold_cnn: f32,        // Default: 0.5
}

impl MlClassifier {
    pub fn load(model_dir: &Path) -> Result<Self, Error>;

    /// Returns (is_malicious, confidence 0.0-1.0, model_used)
    pub fn classify(&self, data: &[u8], path: &Path) -> MlResult;
}

pub struct MlResult {
    pub is_malicious: bool,
    pub confidence: f32,       // 0.0 = certainly clean, 1.0 = certainly malicious
    pub model: &'static str,   // "gbdt" or "cnn"
    pub label: String,         // "Malware.ML.Generic" or "Malware.ML.Packed" etc.
}
```

**Scanner integration:**
- In `scanner::scan_file()`, after hash checks, pattern checks, and heuristic checks, run:
  ```
  if let Some(ref ml) = ml_classifier {
      let ml_result = ml.classify(&data, path);
      if ml_result.is_malicious {
          threats.push(format!("ML:{} ({:.0}%)", ml_result.label, ml_result.confidence * 100.0));
      }
  }
  ```
- The ML classifier is created once at startup and shared via `Arc<MlClassifier>`
- If ONNX models are not present, ML classification is silently skipped (graceful degradation)

#### 3.7 Model Update Mechanism
- Models are versioned files: `gbdt_v1.onnx`, `cnn_v1.onnx`
- `voidshield update` checks for model updates alongside signature updates
- Host models on a release page (GitHub Releases or a CDN) — they change rarely (monthly retrain)
- Model metadata file (`model_manifest.json`) tracks version, hash, training date, performance metrics

#### 3.8 Confidence Thresholds and False Positive Control
- GBDT threshold tuned for <0.01% FP rate on system binaries (critical — false positives on `/usr/bin/gcc` destroy user trust)
- Allow user override: `voidshield scan --ml-threshold 0.8` (higher = fewer detections, fewer FP)
- "ML detections" shown separately from signature detections in scan output, clearly labeled
- Users can whitelist files that ML flags incorrectly: `voidshield whitelist add <path>`

---

## Implementation Order

1. **C++ Heuristics Module** (1-2 weeks)
   - Start with PE analyzer (most malware targets Windows, largest training value)
   - Build FFI layer and `build.rs` integration
   - Wire into `scanner::heuristic_scan()` to replace the basic checks
   - Test with TheZoo samples

2. **Network Protection** (2-3 weeks)
   - DNS proxy with blocklist first (immediate value, straightforward)
   - Passive packet monitoring with `pnet` second
   - Beacon detection and exfil detection third
   - Add CLI commands and integrate with firewall module

3. **ML Classifier** (2-4 weeks)
   - Download EMBER dataset, train GBDT immediately (can be done in a day)
   - Build feature extractor in Rust (reuses C++ heuristics for PE/ELF parsing)
   - Integrate ONNX Runtime, ship GBDT model
   - CNN model is Phase 2 — train after accumulating enough raw samples from MalwareBazaar

Total estimated timeline: 5-9 weeks for all three features.

---

## Dependency Summary

### New Rust Crates
```toml
# C++ FFI build
cc = "1"                                    # C++ compilation in build.rs

# Network protection
pnet = "0.35"                               # Packet capture
trust-dns-resolver = "0.24"                 # DoH client
trust-dns-server = "0.24"                   # Local DNS listener
tokio = { version = "1", features = ["full"] }  # Async runtime for network

# ML classifier
ort = "2"                                   # ONNX Runtime bindings
```

### System Dependencies
- **LIEF** — PE/ELF/Mach-O parser (C++ static lib, vendored or system)
- **Capstone** — Disassembly engine (C static lib, `pacman -S capstone`)
- **ONNX Runtime** — ML inference (`pacman -S onnxruntime` or bundled)
- **libpcap** — Required by `pnet` for packet capture (`pacman -S libpcap`)
