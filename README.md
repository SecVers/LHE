# LHE (Lightweight Heuristic Engine)

**LHE (Lightweight Heuristic Engine)** is a lightweight, local-first Windows security tool focused on mitigating **info-stealers, droppers, ransomware, and script-based attacks** using **behavior + context heuristics** instead of signature databases.

It’s designed to be useful even when:

- your traditional antivirus is disabled,
- malware is very new (no signatures yet),
- or attackers abuse built-in Windows tools (LOLBins).

LHE is **not** a replacement for a professional AV/EDR. It’s an additional defensive layer meant to reduce exposure to common real-world attack patterns.

---

## Why this exists

A lot of modern malware doesn’t start with “run obviously-malicious.exe”.
It starts with:

- scripts and interpreters,
- LOLBins (Living Off The Land binaries),
- suspicious parent → child process chains,
- payload staging in user-writable locations,
- rapid file modification meant to outrun detection.

LHE aims to make those patterns **louder, harder, and riskier** for attackers.

---

## Threat model

LHE tries to make the following attack patterns harder or noisier:

### Stealers / loaders launched from risky locations
Examples:
- `Downloads`, `Temp`, roaming profile, and other user-writable folders
- Startup / Run locations

### Droppers that stage payloads on disk
Examples:
- unpacking or decrypting payloads
- writing new executable files
- immediately executing secondary payloads

### Script-based attacks & LOLBin abuse
Targets tools such as:
- `powershell.exe`, `cmd.exe`, `python.exe`, `node.exe`, `java.exe`
- `wscript.exe`, `cscript.exe`, `mshta.exe`
- downloaders/LOLBins: `curl.exe`, `wget.exe`, `bitsadmin.exe`, `certutil.exe`

### Suspicious process chains (parent → child)
Examples:
- Office / PDF / Media players spawning PowerShell or script hosts
- cracked tools spawning hidden shells
- “installer” processes launching interpreters from non-system paths

### Ransomware-style file modification bursts
Examples:
- rapid file edits across user folders
- high-entropy file writes that resemble encryption

---

## What LHE is *not*

LHE does **not**:

- maintain a global cloud reputation database,
- guarantee 100% detection of all threats,
- provide deep memory scanning via a kernel driver,
- replace a managed endpoint solution.

---

## Key features (current)

### Runtime Guard (process start monitoring)
Monitors every new process and evaluates:
- launch location (path context)
- signature state and signer (when available)
- risky execution origins (user-writable paths)

If a process is considered unsafe, LHE can terminate it and quarantine the executable.

### Risk Assessment Engine (suspicious file scanning)
When enabled, LHE scans newly executed files to detect dropper-like traits:
- high entropy (packed/encrypted/obfuscated hints)
- weak or unusual string statistics
- dropper/decryption indicators

It then presents a human-readable popup with reasons and actions (delete, open location, ignore).

### Interpreter Guard (LOLBin + script host protection)
A dedicated guard inspects command lines for:
- suspicious interpreter locations (AppData/Temp/etc.)
- encoded/obfuscated commands (e.g., `-enc`, `\u`, `\x`)
- downloader chains (`curl`, `wget`, `bitsadmin`, `certutil`)

It can block unsafe invocations and supports an optional whitelist for game launchers.

### Office Protection (process genealogy)
Watches for risky parent → child chains such as:
- Office or PDF apps spawning PowerShell, cmd, wscript, mshta, rundll32, etc.

Suspicious chains can be terminated to prevent macro/dropper execution.

### Ransomware Detection
Monitors file system activity to spot bursty modification patterns and high-entropy writes.
Suspicious processes are suspended, and a decision dialog lets the user allow or terminate them.

### Memory Forensic Detection
Performs lightweight scans for suspicious memory regions:
- private executable + writable regions
- optional thread-context checks

This adds a basic layer of in-memory anomaly detection without a kernel driver.

### Trusted publisher model (false-positive reduction)
LHE can avoid flagging known signed vendors (OS vendors, browsers, OEMs, dev tools, etc.).

### Tray-based controls
All protections can be toggled via the system tray:
- Interpreter Guard + Whitelist
- Office Protection
- Runtime Guard
- Risk Assessment Engine
- Ransomware Detection
- Memory Forensic Detection

---

## Data & networking

LHE’s detection logic is local-first and does not require cloud lookups or signature updates. The codebase includes optional telemetry/update-check components, but they are not wired into the runtime by default unless you integrate them.

---

## Safety notice

LHE may:
- kill processes
- quarantine / rename executables
- suspend or terminate suspicious tasks

Use it responsibly and preferably together with:
- a solid backup strategy
- sensible browser/download hygiene
- (ideally) a normal antivirus/endpoint solution

You are responsible for what you run and what you allow.

---

## Project status

This repository contains the LHE project and its evolving feature set.
Expect changes as heuristics and protections improve.

---

## Related projects

LHE started as an optional layer for **SecVers Debloat**, but it is now maintained as a standalone project.
Integration is still possible, but not required.

---

## Contributing

Contributions are welcome, especially:
- heuristic rules with clear rationale + examples
- false-positive reduction improvements
- clearer user-facing explanations (why something got blocked)
- test cases for suspicious command-lines and process chains

Open an issue first for larger changes to avoid duplicated work.

---

## License

Licensed under the **BSD 3-Clause** license. See `LICENSE`.

---

## Disclaimer

This tool is provided “as is”, without warranty of any kind.  
Security tools reduce risk, they don’t eliminate it.
