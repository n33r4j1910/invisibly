# Invisibly

*Your computer can be compromised without a single virus.*

Invisibly continuously verifies that your Windows security configuration remains trustworthy, detects unauthorized changes, and automatically restores safe settings — all completely offline.

## Why Invisibly?

Antivirus scans for malicious files. Invisibly watches the security settings that malware changes instead. Most successful attacks don't drop malware at all — they modify DNS, disable the firewall, add persistence, or quietly weaken your defenses. Invisibly monitors these security controls and restores them when it's safe to do so.

**No cloud. No telemetry. No AI. Everything runs locally.**

## Design Philosophy

Invisibly is not:

- an antivirus
- an EDR
- a SIEM
- a vulnerability scanner
- a network IDS

Instead, it acts as a continuous endpoint integrity monitor. Think of it as the smoke alarm for your computer.

## Core Principles

Offline by design · Privacy first · Lightweight · Automatic repair where safe · Self-healing infrastructure · Human-readable alerts · Zero telemetry · Minimal resource usage · Everything stays on your device.

## Feature Comparison

| Capability | Antivirus | Firewall | EDR | Invisibly |
|---|:---:|:---:|:---:|:---:|
| **Core Protection** | | | | |
| Malware Scanning | ✅ | ❌ | ✅ | ❌ |
| Virus Signature Updates | ✅ | ❌ | ✅ | ❌ |
| File Quarantine | ✅ | ❌ | ✅ | ❌ |
| **Configuration Integrity** | | | | |
| Endpoint Integrity Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Integrity Score | ❌ | ❌ | ⚠️ | ✅ |
| Automatic Security Repair | ❌ | ❌ | ⚠️ | ✅ |
| Configuration Drift Detection | ❌ | ❌ | ⚠️ | ✅ |
| **Network Protection** | | | | |
| DNS Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Hosts File Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Proxy Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| ARP Spoofing Detection | ❌ | ❌ | ❌ | ✅ |
| New Network Device Detection | ❌ | ❌ | ⚠️ | ✅ |
| Brute-force Detection | ❌ | ❌ | ⚠️ | ✅ |
| **Windows Security Controls** | | | | |
| Windows Firewall Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Windows Defender Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| UAC Monitoring | ❌ | ❌ | ❌ | ✅ |
| Windows Update Monitoring | ❌ | ❌ | ❌ | ✅ |
| System Restore Monitoring | ❌ | ❌ | ❌ | ✅ |
| SmartScreen Monitoring | ❌ | ❌ | ❌ | ✅ |
| Secure Boot Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| LAPS Monitoring | ❌ | ❌ | ❌ | ✅ |
| **Persistence Monitoring** | | | | |
| Startup Entry Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Scheduled Task Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Windows Services Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| **Hardware Protection** | | | | |
| HID Device Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Bluetooth Device Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Unknown Network Adapter Detection | ❌ | ❌ | ⚠️ | ✅ |
| **Threat Detection** | | | | |
| Homoglyph Domain Detection | ❌ | ❌ | ❌ | ✅ |
| Unicode Bidi / Zero-width Attack Detection | ❌ | ❌ | ❌ | ✅ |
| Suspicious Process Detection | ⚠️ | ❌ | ⚠️ | ✅ |
| Real-Time Ransomware Pattern Detection | ⚠️ | ❌ | ⚠️ | ✅ |
| **Privacy & Performance** | | | | |
| Fully Offline Operation | ⚠️ | ✅ | ❌ | ✅ |
| No Cloud Dependency | ❌ | ✅ | ❌ | ✅ |
| No Telemetry | ❌ | ✅ | ❌ | ✅ |
| Typical RAM Usage | 200–500 MB | <50 MB | 500 MB–2 GB | ~30 MB |

*⚠️ = Partial or vendor-dependent*

## Security Testing Results

Invisibly has been tested through multiple independent security platforms to verify its safety and legitimacy.

| Test Platform | Result |
|---|---|
| VirusTotal (70 engines) | 65/70 clean — 5 false positives from behavioral/AI engines |
| CAPE Sandbox | 0/100 malicious score — all behaviors are by design |
| MITRE ATT&CK Mapping | 33 techniques observed — all expected for a security tool |
| Sigma Rules | 1 HIGH, 1 MEDIUM, 3 LOW — all false positives from expected PowerShell monitoring |

## What Invisibly Monitors

Invisibly watches the security settings that attackers target — 35 signals in total.

**Network (12 signals)**

- DNS configuration
- Hosts file
- Proxy settings
- ARP table
- Network adapters
- WiFi SSID and network profile (public/private)
- VPN state
- New network devices
- DHCP configuration
- DNS-over-HTTPS status
- IPv6 status

**Security Controls (11 signals)**

- Windows Firewall
- Windows Defender
- User Account Control (UAC)
- Windows Update
- System Restore
- SmartScreen
- Secure Boot
- LAPS
- BitLocker *(requires a BitLocker-capable Windows edition and a TPM — see note below)*
- Credential Guard
- Windows Event Log

**Persistence (3 signals)**

- Startup entries
- Scheduled tasks
- Windows Services

**Hardware (2 signals)**

- HID devices (keyboard/mouse)
- Bluetooth devices

**Active Attacks (4 signals)**

- Brute force login attempts — automatically blocked at the firewall
- Remote Desktop (RDP) unexpectedly enabled — automatically disabled
- Suspicious processes (running from Temp/Downloads/Desktop)
- Unexpected new software installed

**Social Engineering (3 signals)**

- Homoglyph domains
- Unicode bidi / zero-width character attacks (hidden characters disguising a redirect)
- Fake file extensions (e.g. `invoice.pdf.exe`)

> **Note on BitLocker:** BitLocker Drive Encryption isn't available on every Windows setup — it needs a BitLocker-capable edition (Pro/Enterprise/Education) and a TPM. On Windows Home or hardware without a TPM, that specific check has nothing to report; Invisibly detects this and stays quiet rather than alerting on a status it can't determine. Every other signal is unaffected.

## Behavior-Based Detection

Invisibly doesn't just check for known threats — it detects **any** change to your security configuration.

| Change Type | How It's Detected |
|---|---|
| DNS changed | Detected as configuration drift |
| Firewall disabled | Detected as configuration drift |
| New device connected | Detected as a hardware change |
| UAC disabled | Detected as a security control change |
| Windows Update disabled | Detected as a service change |
| **Any future threat** | **Detected as a configuration change** |

This means Invisibly catches **unknown threats** too — not just pre-defined signatures.

*One exception to the 30-second cycle:* ransomware can finish encrypting a folder faster than a 30s check can catch it. See **Real-Time Ransomware Watch** below — it's the one thing in Invisibly that reacts instantly instead of on the next cycle.

## Integrity Score

Every system receives a score between 0 and 100 based on current state — not historical events.

*Example:*

- Firewall: Healthy
- Defender: Healthy
- DNS: Warning (-12 points)
- System Health: 88/100

## Security Timeline

Every event is recorded in an append-only, tamper-evident timeline.

*Example:*

- 14:02 — DNS changed → Restored
- 14:03 — Integrity Score: 100
- 14:05 — RDP enabled → Disabled automatically

## Baseline Protection

The baseline is:

- Cryptographically signed (HMAC-SHA256)
- Versioned, with rollback protection
- Tamper-detected
- Signing key protected at rest with Windows DPAPI, tied to your Windows account — not stored as a plain file
- Self-healing for infrastructure problems (a locked-down data folder, a stale signature from a benign cause); a genuinely tampered executable never self-heals — it's always surfaced to you instead

If the baseline is tampered with and the executable itself checks out clean, the daemon regenerates it automatically. If the executable itself fails its own signature check, auto-repair disables and the daemon shows a clear alert (dashboard banner, tray icon, notification) rather than fixing anything silently.

## Ghost Mode (Public WiFi)

Auto-enables on public networks, auto-disables when you're back on a trusted one. Deliberately inbound-only — it never touches outbound traffic, so it can't break your internet:

- Blocks risky inbound ports
- Blocks inbound ICMP
- Disables Network Discovery and file sharing

## Real-Time Ransomware Watch

Watches Documents, Desktop, Pictures, and Downloads live — not on the usual 30-second cycle. If it sees a burst of 20+ file changes within 10 seconds (the signature of mass encryption, not a normal edit), it alerts immediately:

- Instant tray alert (highest priority — above even a tamper alert) and dashboard banner
- Alert-only, not auto-kill: this tells you *what* changed, not *which process* did it, so there's no reliable target to automatically terminate yet
- Auto-clears once file activity settles down
- Fixed to these four folders on purpose — not user-editable yet, and deliberately not extended to a whole drive (more folders means more background noise, and Windows can start silently dropping change notifications under heavy load)

## System Tray

| Color | Status |
|---|---|
| 🟢 Green | System maintained |
| 🟡 Yellow | Drift detected |
| 🔴 Red | Critical issues; a security alert (executable tamper check failed); or (highest priority) possible ransomware activity detected in real time |
| 🔵 Blue | Ghost Mode active |
| ⚪ Gray | Daemon offline, or running without admin rights (limited protection) |

## Performance

| Metric | Value |
|---|---|
| RAM | ~30 MB |
| CPU (idle) | <0.1% |
| Disk | <20 MB |
| Network | Localhost only |

## Quick Start (MSIX)

1. **Download and install** — download `Invisibly.msix` and double-click to install.
2. **Launch** — open Invisibly from the Start menu. On first run it creates a Windows Scheduled Task so it can run with full privileges at every login, without a permission prompt each time; until that first elevated run, it operates in monitor-only mode (detects and alerts, doesn't auto-repair).
3. This starts the daemon and tray automatically at every login from then on — no manual launch needed.
4. **Optional — set Home WiFi**: supported via the daemon's local API (`POST /home`); not yet exposed as a dashboard button.

## Dashboard

Right-click the tray icon, or open:

```
http://127.0.0.1:12790/dashboard
```

**Controls:**

- Enable/Disable Ghost Mode
- Run Auto-Repair
- Reset Baseline
- Rollback Changes
- Verify Trust
- Restart Daemon
- Sanitize (clean up logs/temp data)

## Requirements

- Windows 10/11 (64-bit)
- Administrator privileges for auto-repair

## Keywords

endpoint integrity, configuration monitoring, behavior-based detection, DNS hijacking, ARP spoofing, hosts file protection, firewall monitoring, defender monitoring, UAC protection, Windows Update monitoring, System Restore protection, SmartScreen monitoring, Bluetooth security, HID protection, RDP protection, homoglyph detection, zero-width attacks, Unicode bidi attacks, brute force detection, proxy monitoring, scheduled tasks monitoring, startup persistence, Windows Services monitoring, Ghost Mode, public WiFi protection, stealth mode, integrity score, trust level, security baseline, auto-repair, self-healing, tamper detection, DPAPI encryption, ransomware detection, real-time file monitoring, configuration drift detection, offline security, no telemetry, privacy-first, lightweight, Windows security, Rust, autonomous endpoint protection, security timeline

## License

*Proprietary — All Rights Reserved*

© 2026 DeltaIQx LLP
