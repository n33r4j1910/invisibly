* Invisibly *

*Your computer can be compromised without a single virus.*


Invisibly continuously verifies that your Windows security configuration remains trustworthy, detects unauthorized changes, and automatically restores safe settings — all completely offline.


* Why Invisibly ? *

Antivirus scans for malicious files. Invisibly watches the security settings that malware changes. Most successful attacks don't drop malware. They modify DNS, disable firewall, add persistence, or weaken your defenses. Invisibly monitors these security controls and restores them when safe.

*No cloud. No telemetry. No AI. Everything runs locally.*


* Design Philosophy *

Invisibly is not:

* an antivirus
* an EDR
* a SIEM
* a vulnerability scanner
* a network IDS

Instead, it acts as a continuous endpoint integrity monitor. Think of it as the smoke alarm for your computer.


* Core Principles - Privacy *


Offline by design, Privacy first, Lightweight, Automatic repair where safe, Self-healing infrastructure, Human-readable alerts, Zero telemetry, Minimal resource usage, Everything stays on your device.


* Feature Comparison *				

		
Capability	      		  Antivirus  Firewall  EDR  Invisibly 


*Core Protection* 				

Malware Scanning 	 	 	✅ 	 ❌ 	 ✅ 	 ❌ 

Virus Signature Updates 	 	✅ 	 ❌ 	 ✅ 	 ❌ 

File Quarantine 	 	 	✅ 	 ❌ 	 ✅ 	 ❌ 

*Configuration Integrity* 				

Endpoint Integrity Monitoring 	 	❌ 	 ❌ 	 ⚠️ 	 ✅ 

Integrity Score 	 	 	❌ 	 ❌ 	 ⚠️ 	 ✅ 

Automatic Security Repair 	 	❌ 	 ❌ 	 ⚠️ 	 ✅ 

Configuration Drift Detection 	 	❌ 	 ❌ 	 ⚠️ 	 ✅ 

**Network Protection** 				

DNS Monitoring 	 	 	 	❌ 	 ❌ 	 ⚠️ 	 ✅ 

Hosts File Monitoring 	 	 	❌ 	 ❌ 	 ⚠️ 	 ✅ 

Proxy Monitoring 	 	 	❌ 	 ❌ 	 ⚠️ 	 ✅ 

ARP Spoofing Detection 	 	 	❌ 	 ❌ 	 ❌ 	 ✅ 

New Network Device Detection 	 	❌ 	 ❌ 	 ⚠️ 	 ✅ 

Brute-force Detection 	 	 	❌ 	 ❌ 	 ⚠️ 	 ✅ 

*Windows Security Controls* 				

Windows Firewall Monitoring 	 	❌ 	 ❌ 	 ⚠️ 	 ✅ 

Windows Defender Monitoring 		❌ 	 ❌ 	 ⚠️ 	 ✅ 

UAC Monitoring 	 	 	 	❌ 	 ❌ 	 ❌ 	 ✅ 

Windows Update Monitoring 	 	❌ 	 ❌ 	 ❌ 	 ✅ 

System Restore Monitoring 	 	❌ 	 ❌ 	 ❌ 	 ✅ 

SmartScreen Monitoring 	 	 	❌ 	 ❌ 	 ❌ 	 ✅ 

Secure Boot Monitoring 	 	 	❌ 	 ❌ 	 ⚠️ 	 ✅ 

LAPS Monitoring 	 	 	❌ 	 ❌ 	 ❌ 	 ✅ 

*Persistence Monitoring* 				

Startup Entry Monitoring 	 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

Scheduled Task Monitoring 	 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

Windows Services Monitoring 	 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

*Hardware Protection* 				

HID Device Monitoring 	 	 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

Bluetooth Device Monitoring 	 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

Unknown Network Adapter Detection 	 ❌ 	 ❌ 	 ⚠️ 	 ✅ 

*Threat Detection* 				

Homoglyph Domain Detection 	 	❌ 	 ❌ 	 ❌ 	 ✅ 

Unicode Bidi / Zero-width Attack Detection 	❌ 	 ❌ 	 ❌ 	 ✅ 

Suspicious Process Detection 	 	⚠️ 	 ❌ 	 ⚠️ 	 ✅ 

*Privacy \& Performance* 				

Fully Offline Operation 	 	⚠️ 	 ✅ 	 ❌ 	 ✅ 

No Cloud Dependency 	 	 	❌ 	 ✅ 	 ❌ 	 ✅ 

No Telemetry 	 		 	❌ 	 ✅ 	 ❌ 	 ✅ 

Typical RAM Usage 		 200–500 MB  <50 MB   500 MB–2 GB  ~30 MB 



*⚠️ = Partial or vendor-dependent*


* Security Testing Results *


Invisibly has been tested through multiple independent security platforms to verify its safety and legitimacy.


Test Platform Result

- VirusTotal (70 engines) - 65/70 clean — 5 false positives from behavioral/AI engines.

- CAPE Sandbox - 0/100 malicious score — All behaviors are by design

- MITRE ATT\&CK Mapping - 33 techniques observed — All expected for security tool

- Sigma Rules - 1 HIGH, 1 MEDIUM, 3 LOW — All false positives from expected PowerShell monitoring



* What Invisibly Monitors *

Invisibly watches the security settings that attackers target.


Network (12 signals)

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



* Behavior-Based Detection *

Invisibly doesn't just check for known threats — it detects **any** change to your security configuration.

| Change Type | How It's Detected |

- DNS changed - Detected as configuration drift

- Firewall disabled - Detected as configuration drift

- New device connected - Detected as hardware change

- UAC disabled | Detected as security control change

- Windows Update disabled - Detected as service change

**ANY future threat** | **Detected as a configuration change**

This means Invisibly catches **unknown threats** too — not just pre-defined signatures.


* Security Controls (11 signals) *

- Windows Firewall

- Windows Defender

- User Account Control (UAC)

- Windows Update

- System Restore

- SmartScreen

- Secure Boot

- LAPS

- BitLocker

- Credential Guard

- Windows Event Log


* Persistence (3 signals) *

- Startup entries

- Scheduled tasks

- Windows Services


* Hardware (2 signals) * 

- HID devices (keyboard/mouse)

- Bluetooth devices


* Active Attacks (4 signals) *

- Brute force login attempts — automatically blocked at the firewall

- Remote Desktop (RDP) unexpectedly enabled — automatically disabled

- Suspicious processes (running from Temp/Downloads/Desktop)

- Unexpected new software installed


* Social Engineering (3 signals) *

- Homoglyph domains

- Unicode bidi / zero-width character attacks (hidden characters disguising a redirect)

- Fake file extensions (e.g. invoice.pdf.exe)



* Integrity Score *

Every system receives a score between 0 and 100 based on current state — not historical events.

*Example:*

- Firewall: Healthy

- Defender: Healthy

- DNS: Warning (-12 points)

- System Health: 88/100


* Security Timeline *

Every event is recorded in an append-only timeline.


*Example:*

- 14:02 DNS changed → Restored

- 14:03 Integrity Score: 100

- 14:05 RDP enabled → Disabled automatically



* Baseline Protection *

The baseline is:

- Cryptographically signed (HMAC-SHA256)

- Versioned, with rollback protection

- Tamper-detected

- Signing key protected at rest with Windows DPAPI, tied to your Windows account — not stored as a plain file

- Infrastructure problems (a locked-down data folder, a stale signature from a benign cause) self-heal automatically; a genuinely tampered executable never does — it's always surfaced to you instead


If the baseline is tampered and the executable itself checks out clean, the daemon regenerates it automatically. If the executable itself fails its own signature check, auto-repair disables and the daemon shows a clear alert (dashboard banner, tray icon, notification) rather than fixing anything silently.


* Ghost Mode (Public WiFi) *


Auto-enables on public networks, auto-disables when you're back on a trusted one. Deliberately inbound-only — never touches outbound traffic, so it can't break your internet:

- Blocks risky inbound ports

- Blocks inbound ICMP

- Disables Network Discovery and file sharing


* System Tray *


| Color | Status |

| 🟢 Green | System maintained |

| 🟡 Yellow | Drift detected |

| 🔴 Red | Critical issues, or (highest priority) a security alert — the app's own executable failed its tamper check |

| 🔵 Blue | Ghost Mode active |

| ⚪ Gray | Daemon offline, or running without admin rights (limited protection) |



* Performance *


| Metric | Value |

- RAM - \~30 MB

- CPU (idle) - <0.1%

- Disk - <20 MB

- Network - Localhost only



* Quick Start (MSIX)*


* Download and Install — Download Invisibly.msix and double-click to install

* Launch — Open Invisibly from the Start menu. On first run it creates a Windows Scheduled Task so it can run with full privileges at every login, without a permission prompt each time; until that first elevated run, it operates in monitor-only mode (detects and alerts, doesn't auto-repair).

* This starts the daemon and tray automatically at every login from then on — no manual launch needed.

* Optional – Set Home WiFi — Click "Set Home WiFi" in the dashboard and enter your network name



* Dashboard - Right click in the tray *


`http://127.0.0.1:12790/dashboard`


* Controls: *

- Enable/Disable Ghost Mode

- Run Auto-Repair

- Reset Baseline

- Rollback Changes

- Verify Trust


* Requirements *

- Windows 10/11 (64-bit)

- Administrator privileges for auto-repair



Keywords

endpoint integrity, configuration monitoring, behavior-based detection, DNS hijacking, ARP spoofing, hosts file protection, firewall monitoring, defender monitoring, UAC protection, Windows Update monitoring, System Restore protection, SmartScreen monitoring, Bluetooth security, HID protection, RDP protection, homoglyph detection, zero-width attacks, Unicode bidi attacks, brute force detection, proxy monitoring, scheduled tasks monitoring, startup persistence, Windows Services monitoring, Ghost Mode, public WiFi protection, stealth mode, integrity score, trust level, security baseline, auto-repair, self-healing, tamper detection, DPAPI encryption, configuration drift detection, offline security, no telemetry, privacy-first, lightweight, Windows security, Rust, autonomous endpoint protection, security timeline

* License *

*Proprietary — All Rights Reserved*

© 2026 DeltaIQx LLP