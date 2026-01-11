# LHE Wiki (Design Draft)

## 1) Overview
LHE (Lightweight Heuristic Engine) is a Windows hardening tool focused on local, behavior-based detection for common attack patterns: LOLBins, script abuse, risky process ancestry, ransomware-like file bursts, and suspicious executable traits.

This wiki is organized to be practical for users and contributors: what each feature does, how it works under the hood, how to troubleshoot, and what limitations are known.

---

## 2) Feature Catalog

### Runtime Guard (Process Monitor)
**What it does:**
- Watches all new process starts via WMI.
- Evaluates the executable path, signature trust, and location risk.
- Quarantines and terminates suspicious binaries (renames with `.SecVersBlocked`).

**Best for:**
- Blocking unsigned malware that launches from user-writable directories.

---

### Risk Assessment Engine (Suspicious File Scanner)
**What it does:**
- Scans newly executed files for entropy, string statistics, and dropper/decryption indicators.
- Produces a human-readable reason list and prompts for action.
- Suspends the process before prompting.

**Best for:**
- Catching packed/encrypted droppers and staged payloads that avoid signatures.

---

### Interpreter Guard (LOLBin + Script Host Protection)
**What it does:**
- Monitors common interpreters and LOLBins (PowerShell, cmd, wscript, mshta, curl, etc.).
- Blocks risky paths (AppData/Temp/ProgramData) and obfuscated command lines.
- Optional whitelist for common game launchers (Steam/Minecraft paths).

**Best for:**
- Preventing one-liner download+execute chains and script-based payloads.

---

### Office Protection (Process Genealogy)
**What it does:**
- Tracks parent → child process chains.
- Kills suspicious children spawned by Office/PDF/media applications (e.g., Office spawning PowerShell).

**Best for:**
- Macro-based attacks and document-borne droppers.

---

### Ransomware Detection
**What it does:**
- Monitors user folders and drives for rapid file modifications.
- Uses entropy + burst thresholds to detect probable encryption behavior.
- Suspends suspect processes and asks the user to allow or terminate them.

**Best for:**
- Early interruption of ransomware-like activity.

---

### Memory Forensic Detection
**What it does:**
- Scans processes for private, executable + writable memory regions.
- Optionally inspects thread contexts for anomalies.

**Best for:**
- Spotting injected or in-memory payloads without a kernel driver.

---

### Trusted Publisher Model
**What it does:**
- Uses a curated signed-vendor list to reduce false positives.
- Protects common OS vendors, browsers, OEMs, and developer tools.

**Best for:**
- Keeping the user experience sane while preserving strict heuristics.

---

### Tray Controls
All protections can be toggled in the system tray:
- Interpreter Guard + Whitelist
- Office Protection
- Runtime Guard
- Risk Assessment Engine
- Ransomware Detection
- Memory Forensic Detection

---

## 3) How It Works (Data Flow)

### Process start pipeline
1. WMI reports a new process start.
2. Runtime Guard checks path risk and signature trust.
3. If the process is unsafe, it is terminated and quarantined.
4. If Risk Assessment Engine is enabled, the file is scanned and a prompt appears.

### Interpreter Guard pipeline
1. WMI reports an interpreter or LOLBin start.
2. Command line is examined for risky paths, obfuscation, or network download patterns.
3. If unsafe, the process is terminated and a tray alert is shown.

### Office Protection pipeline
1. WMI reports a new process start.
2. If parent is Office/PDF/media and child is a risky binary, kill child and parent.
3. Alert user via tray.

### Ransomware pipeline
1. File system watchers monitor key user locations and drives.
2. Rapid or high-entropy modifications raise alert thresholds.
3. Process is suspended; user decides to allow or terminate.
4. Optional whitelisting for the session if allowed.

### Memory Forensic pipeline
1. Periodic scan across processes.
2. Flag executable + writable private memory regions.
3. Optionally validate thread contexts for suspicious states.

---

## 4) Configuration & Controls

- Most features are enabled by default and can be toggled in the tray.
- Interpreter Guard whitelist is **off by default** for strict mode.
- Trust decisions in heuristics are in-memory for the current session (no persistent whitelist UI yet).

---

## 5) Known Limitations / Known Problems

- **WMI event delays:** WMI process start events can miss very short-lived processes or arrive late under heavy load.
- **False positives in AppData/Temp:** Strict path checks can block legitimate software that runs from user-writable locations.
- **Java interpreter handling:** Java executables are intentionally treated as untrusted to avoid signer-based bypasses.
- **Whitelist is simple substring matching:** It can be bypassed by directory name collisions; needs stronger path validation.
- **No kernel driver:** Memory forensics is best-effort and may miss advanced in-memory techniques.
- **Placeholder components:** SSL pinning and suspicious autostart detection are scaffolds and not fully implemented.
- **Telemetry/update modules are present but unused:** Networking helpers exist but are not wired into runtime by default.

---

## 6) Troubleshooting

- **App breaks after enabling Interpreter Guard:**
  - Disable whitelist strict mode, or add launcher paths (Steam/Minecraft) if relevant.
  - Review command lines for encoded or hidden execution flags.

- **Legitimate Office macros blocked:**
  - Temporarily disable Office Protection.
  - Consider whitelisting the macro workflow if safe.

- **Ransomware prompts during bulk file operations:**
  - Allow the process if you initiated the bulk change.
  - Use the allow/terminate dialog carefully to avoid data loss.

- **Performance concerns:**
  - Reduce enabled features or increase scan interval where supported.
  - Keep Memory Forensic Detection on for investigative scenarios only.

---

## 7) Roadmap Ideas

- Persistent and user-editable whitelist UI.
- Safer, stronger path normalization for whitelists.
- Improved telemetry toggles & explicit opt-in/opt-out settings.
- Autostart persistence detection.
- Optional YARA-based scans.

---

## 8) FAQ

**Q: Is LHE a full antivirus?**
A: No. It’s a lightweight heuristic layer meant to complement traditional endpoint protection.

**Q: Does LHE upload my files?**
A: Not by default. The detection pipeline is local-first. Networking helpers exist but are not wired to runtime unless you integrate them.

**Q: Can I disable specific protections?**
A: Yes, via the tray menu.
