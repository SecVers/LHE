# LHE (Lightweight Heuristic Engine)

**LHE (Lightweight Heuristic Engine)** is a lightweight, local-first Windows security tool focused on mitigating **info-stealers, droppers, and script-based attacks** using **behavior + context heuristics** instead of signature databases.

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
- quick execution meant to outrun detection.

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
- Office / PDF / Browser spawning PowerShell or script hosts
- cracked tools spawning hidden shells
- “installer” processes launching interpreters from non-system paths

---

## What LHE is *not*

LHE does **not**:

- maintain a global cloud reputation database,
- guarantee 100% detection of all threats,
- provide deep memory scanning,
- provide kernel-level protection.

---

## High-level features

### Real-time process monitoring
Every new process can be evaluated for:
- launch location (path context)
- signature state and signer (when available)
- known-safe system/vendor binaries
- risky execution origins (user-writable paths)

### Heuristic risk scoring
Suspicious binaries can be scored by:
- location (Downloads / Temp / Startup)
- signature state (unsigned / unknown signer)
- metadata hints (company/product fields)
- behavior patterns (via additional scanners)

### Suspicious file scanning
The **SuspiciousFileScanner** can analyze potentially dangerous executables by:
- calculating entropy (packed/encrypted/obfuscated hints)
- extracting strings and searching for common dropper/stealer patterns
- producing:
  - a suspicion score
  - human-readable reasons
- presenting a popup where the user can:
  - open file location
  - delete/quarantine the file (if enabled)
  - explicitly ignore it (at their own risk)

### Interpreter / LOLBin guard
A dedicated guard inspects command lines of common tools such as:
- `python.exe`, `java.exe`, `node.exe`
- `powershell.exe`, `pwsh.exe`, `cmd.exe`
- `wscript.exe`, `cscript.exe`, `mshta.exe`
- `curl.exe`, `wget.exe`, `bitsadmin.exe`, `certutil.exe`

It can flag/block patterns like:
- `-enc`, `-encodedcommand`
- heavy obfuscation (`%00`, `\u`, `\x`, etc.)
- hidden window execution + non-system paths
- downloader + execute chains

### Process genealogy checks (who started what)
**ProcessGenealogy** watches parent → child relationships to:
- identify suspicious chains
- block or kill the child process
- optionally terminate the parent if necessary
- report activity via tray notifications

### Trusted publisher model (reduce false positives)
To reduce noise, LHE can:
- use a curated trusted publisher list (OS vendors, OEMs, major vendors, dev tools, platforms)
- validate Authenticode signatures when possible
- treat signed interpreters carefully (signed ≠ safe payload)

### Local-first, lightweight, no cloud
All analysis is designed to be local:
- no online lookups
- no data sent to external servers
- no signature DB updates needed

---

## Safety notice

LHE may:
- kill processes
- quarantine / rename executables
- optionally employ self-protection

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
