**# Invisibly**



\*\*Your computer can be compromised without a single virus.\*\*



Invisibly continuously verifies that your Windows security configuration remains trustworthy, detects unauthorized changes, and automatically restores safe settings — all completely offline.



\---



**## Why Invisibly?**



Antivirus scans for malicious files. Invisibly watches the security settings that malware changes.



Most successful attacks don't drop malware. They modify DNS, disable firewall, add persistence, or weaken your defenses.



Invisibly monitors these security controls and restores them when safe.



\*\*No cloud. No telemetry. No AI. Everything runs locally.\*\*



\---



**Design Philosophy**



Invisibly is not:



* an antivirus
* an EDR
* a SIEM
* a vulnerability scanner
* a network IDS



Instead, it acts as a continuous endpoint integrity monitor. Think of it as the smoke alarm for your computer.



\---



**Core Principles - Privacy**



Offline by design

Privacy first

Lightweight

Automatic repair where safe

Human-readable alerts

Zero telemetry

Minimal resource usage



Everything stays on your device.





**## What Invisibly Monitors**



Invisibly watches the security settings that attackers target.



\### Network (8 signals)

\- DNS configuration

\- Hosts file

\- Proxy settings

\- ARP table

\- Listening ports

\- Network adapters

\- WiFi SSID

\- VPN state



\### Security Controls (8 signals)

\- Windows Firewall

\- Windows Defender

\- User Account Control (UAC)

\- Windows Update

\- System Restore

\- SmartScreen

\- Secure Boot

\- LAPS



\### Persistence (3 signals)

\- Startup entries

\- Scheduled tasks

\- Windows Services



\### Hardware (3 signals)

\- USB storage

\- HID devices (keyboard/mouse)

\- Bluetooth devices



\### Active Attacks (5 signals)

\- Port scanning

\- Brute force login attempts

\- Phishing domains in DNS cache

\- Ransomware canary files

\- Suspicious processes



\### Social Engineering (3 signals)

\- Homoglyph domains

\- Unicode bidi attacks

\- Zero-width character injection



\---



**## Integrity Score**



Every system receives a score between 0 and 100 based on current state — not historical events.



\*\*Example:\*\*

\- Firewall: Healthy

\- Defender: Healthy

\- DNS: Warning (-12 points)

\- System Health: 88/100



\---



**## Security Timeline**



Every event is recorded in an append-only timeline.



\*\*Example:\*\*

\- 14:02 DNS changed → Restored

\- 14:03 Integrity Score: 100

\- 14:05 USB inserted → Ejected



Export as JSON or Markdown for incident response.



\---



**## Baseline Protection**



The baseline is:

\- Cryptographically signed (HMAC-SHA256)

\- Versioned

\- Tamper-detected

\- TPM optional (falls back to HMAC)



If the baseline is tampered → system enters \*\*Invalid\*\* state → manual verification required.



\---



**## Ghost Mode (Public WiFi)**



Auto-enables on public networks:

\- Blocks all inbound connections

\- Blocks all outbound except VPN

\- Disables Network Discovery

\- Disables Bluetooth

\- Blocks 26 malicious ports



\---



**## System Tray**



| Color | Status |

|-------|--------|

| 🟢 Green | System maintained |

| 🟡 Yellow | Drift detected |

| 🔴 Red | Critical issues |

| 🔵 Blue | Ghost Mode active |

| ⚪ Gray | Daemon offline |



\---



**## Performance**



| Metric | Value |

|--------|-------|

| RAM | \~30 MB |

| CPU (idle) | <0.1% |

| Disk | <20 MB |

| Network | Localhost only |



\---



**# Feature Comparison**				

&#x09;				

&#x09;			

&#x20;**Capability 	 	Antivirus 	 Firewall 	 EDR 	 Invisibly** 

&#x20;

**\*\*Core Protection\*\*** 				

&#x20;Malware Scanning 	 	 ✅ 	 ❌ 	 ✅ 	 ❌ 

&#x20;Virus Signature Updates 	 ✅ 	 ❌ 	 ✅ 	 ❌ 

&#x20;File Quarantine 	 	 ✅ 	 ❌ 	 ✅ 	 ❌ 

&#x20;**\*\*Configuration Integrity\*\*** 				

&#x20;Endpoint Integrity Monitoring 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;Integrity Score 	 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;Automatic Security Repair 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;Configuration Drift Detection 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;**\*\*Network Protection\*\*** 				

&#x20;DNS Monitoring 	 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;Hosts File Monitoring 	 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;Proxy Monitoring 	 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;ARP Spoofing Detection 	 ❌ 	 ❌ 	 ❌ 	 ✅ 

&#x20;Port Scan Detection 	 	 ❌ 	 ⚠️ 	 ⚠️ 	 ✅ 

&#x20;Brute-force Detection 	 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;**\*\*Windows Security Controls\*\*** 				

&#x20;Windows Firewall Monitoring 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;Windows Defender Monitoring 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;UAC Monitoring 	 	 ❌ 	 ❌ 	 ❌ 	 ✅ 

&#x20;Windows Update Monitoring 	 ❌ 	 ❌ 	 ❌ 	 ✅ 

&#x20;System Restore Monitoring 	 ❌ 	 ❌ 	 ❌ 	 ✅ 

&#x20;SmartScreen Monitoring 	 ❌ 	 ❌ 	 ❌ 	 ✅ 

&#x20;Secure Boot Monitoring 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;LAPS Monitoring 	 	 ❌ 	 ❌ 	 ❌ 	 ✅ 

&#x20;**\*\*Persistence Monitoring\*\*** 				

&#x20;Startup Entry Monitoring 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;Scheduled Task Monitoring 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;Windows Services Monitoring 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;**\*\*Hardware Protection\*\*** 				

&#x20;USB Storage Monitoring 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;HID Device Monitoring 	 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;Bluetooth Device Monitoring 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;**\*\*Threat Detection\*\*** 				

&#x20;Phishing Domain Detection 	 ⚠️ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;Homoglyph Domain Detection 	 ❌ 	 ❌ 	 ❌ 	 ✅ 

&#x20;Zero-width Character Detection  ❌ 	 ❌ 	 ❌ 	 ✅ 

&#x20;Unicode Bidi Detection 	 ❌ 	 ❌ 	 ❌ 	 ✅ 

&#x20;Ransomware Canary Monitoring 	 ⚠️ 	 ❌ 	 ⚠️ 	 ✅ 

&#x20;**\*\*Privacy \& Performance\*\*** 				

&#x20;Fully Offline Operation 	 ⚠️ 	 ✅ 	 ❌ 	 ✅ 

&#x20;No Cloud Dependency 	 	 ❌ 	 ✅ 	 ❌ 	 ✅ 

&#x20;No Telemetry 	 		 ❌ 	 ✅ 	 ❌ 	 ✅ 

&#x20;Typical RAM Usage 	 200–500 MB 	 <50 MB 	 500 MB–2 GB 	 \*\*\~30 MB\*\* 





**⚠️ = Partial or vendor-dependent**



**## Security Testing Results**



Invisibly has been tested through multiple independent security platforms to verify its safety and legitimacy.



| Test Platform | Result |

|---------------|--------|

| \*\*VirusTotal (70 engines)\*\* | 65/70 clean — 5 false positives from behavioral/AI engines |

| \*\*CAPE Sandbox\*\* | 0/100 malicious score — All behaviors are by design |

| \*\*MITRE ATT\&CK Mapping\*\* | 33 techniques observed — All expected for security tool |

| \*\*Sigma Rules\*\* | 1 HIGH, 1 MEDIUM, 3 LOW — All false positives from expected PowerShell monitoring |



**### What the results mean**



\- The 5 VirusTotal detections are \*\*false positives\*\* from generic behavioral/AI engines

\- CAPE Sandbox confirmed Invisibly only:

&#x20; - Connects to `localhost:12790` (no external network)

&#x20; - Writes only to `C:\\ProgramData\\Invisibly\\`

&#x20; - Reads registry keys (never modifies)

&#x20; - Spawns PowerShell for system queries (expected behavior)



**### Key takeaway**



Invisibly is clean. The security detections are from engines flagging legitimate security tools — not from malicious behavior.



\---



**## Quick Start (MSIX)**



* Download and Install — Download Invisibly.msix and double-click to install



* Launch — Open Command Prompt as Administrator and run: (text) invisibly



* This starts the daemon, tray, and opens the dashboard automatically.



* Optional – Set Home WiFi — Click "Set Home WiFi" in the dashboard and enter your network name



\---



**## Dashboard**



`http://127.0.0.1:12790/dashboard`



\*\*Controls:\*\*

\- Enable/Disable Ghost Mode

\- Run Auto-Repair

\- Reset Baseline

\- Rollback Changes

\- Verify Trust



\---



**## Requirements**



\- Windows 10/11 (64-bit)

\- Administrator privileges for auto-repair



\---



\## Keywords



endpoint integrity, configuration monitoring, DNS hijacking, ARP spoofing, 

hosts file protection, firewall monitoring, defender monitoring, UAC protection, 

Windows Update monitoring, System Restore protection, SmartScreen monitoring, 

USB security, Bluetooth security, HID protection, BadUSB prevention, 

phishing domains, homoglyph detection, zero-width attacks, Unicode bidi attacks, 

ransomware canary, brute force detection, port scan detection, proxy monitoring, 

scheduled tasks monitoring, startup persistence, Windows Services monitoring, 

Ghost Mode, public WiFi protection, stealth mode, integrity score, trust level, 

security baseline, auto-repair, configuration drift detection, offline security, 

no telemetry, privacy-first, lightweight, Windows security, Rust, 

autonomous endpoint protection



**## License**



\*\*Proprietary — All Rights Reserved\*\*



© 2026 DeltaIQx LLP



