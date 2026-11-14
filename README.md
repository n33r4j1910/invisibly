# Invisibly

*Your computer can be compromised without a single virus.*

**Invisibly is a silent guard for your Windows PC. It notices when something quietly changes your security settings — hijacked internet (DNS), a switched-off firewall or Defender, fake security certificates, new startup programs — and puts things right automatically.**

- **Works offline.** Everything runs on your own computer. No account, no sign-in, no cloud.
- **Captures nothing about you.** No name, email, files, passwords or browsing history is read or sent. No telemetry, no tracking.
- **Nothing to manage.** You see one thing: *Protected*.

Antivirus catches known bad files. Invisibly catches the quiet changes that attacks leave behind — the ones your antivirus has nothing to scan for.

## What it does, in plain words

Your PC has settings that keep you safe: the firewall (the gate that blocks unwanted connections), Windows Defender (Windows' built-in antivirus), and the "address book" that decides which website you reach when you type a name (DNS). Attackers know the easiest way in is often not a virus — it's quietly switching one of these off or changing it. Windows won't tell you when that happens, and your antivirus isn't looking at settings.

Invisibly remembers how your settings *should* look, checks them about every 30 seconds, and when something changes that you didn't change, it puts it back. If a decision really needs a person, it tells you in one clear sentence.

Under the hood, it continuously verifies that your Windows security configuration remains trustworthy, detects unauthorized changes, and restores safe settings.

## Why Invisibly?

Antivirus looks for bad *files*. Invisibly looks for bad *changes*. Most successful attacks don't drop malware at all — they modify DNS, disable the firewall, add persistence (a way to start again after a reboot), or quietly weaken your defenses. Invisibly monitors these security controls and restores them when it's safe to do so.

**A real example:** a piece of malware doesn't need to install anything you'd notice — it just quietly disables your firewall and adds itself to Windows startup so it survives a reboot. Windows won't warn you about either change; your antivirus has nothing to scan, since no file it recognizes as malicious was ever dropped. Invisibly catches both changes within about 30 seconds and restores them automatically.

## How this helps you beyond what Windows already gives you

**In plain words:** Windows already has a firewall, Defender and other protections. Invisibly doesn't replace them — it makes sure nobody has quietly switched them off. Concretely:

- **Defender gets disabled — or told to ignore a folder** (by malware, a rogue app, or an accidental click) → Windows stays silent about it. *Why it matters: a switched-off or blinded antivirus is how malware gets a free pass.* Invisibly alerts you, can turn Defender back on, and removes a risky "ignore this folder" rule (a Defender exclusion) the moment it appears.
- **A protection gets quietly switched off** — Tamper Protection (which stops other programs from turning Defender off), the shield around your Windows sign-in secrets (LSASS protection), the old unsafe SMBv1 file-sharing method → Windows doesn't announce it. *Why it matters: these are the locks attackers pick before stealing passwords or spreading to other PCs.* Invisibly notices and, where it's safe, switches them back.
- **DNS or your hosts file gets silently redirected** — a common way to steal banking or email logins by pointing a real-looking address at a fake site → neither Windows nor a normal antivirus checks for this. *Why it matters: you can type your bank's real address and still land on a copy.* Invisibly checks, continuously.
- **Remote Desktop (RDP) gets turned on** without you doing it — a classic sign someone already has a foothold on your machine → *Why it matters: it lets a stranger control your PC from far away.* Invisibly catches it and disables it automatically.
- **A malicious root certificate gets installed** — this lets an attacker silently read traffic you think is secure (the padlock icon still shows) → there's no Windows setting that flags this. *Why it matters: the padlock stops meaning "private".* Invisibly flags it.
- **Something adds itself to startup, a scheduled task, or a background service** — how most malware survives a reboot → you'd otherwise have to know where to look in Task Manager. *Why it matters: it's how a bad program keeps coming back.* Invisibly checks automatically.

## Quiet by design

**In plain words:** Invisibly only interrupts you when a person needs to make a call. Everything else is handled without a word:

- **Fixed on its own (where it's safe):** the changes described above, plus hidden start-up hooks and a stopped Windows Event Log (the PC's activity diary).
- **Noted quietly:** harmless changes — a new program installed, a Wi-Fi network switch, a new Bluetooth device — are learned as normal ("accepted" into the baseline) and counted in the **This week** summary on the dashboard. No pop-up.
- **Alerts you:** only what needs a human decision — a new user account, a new remote-access tool, a new trusted certificate, a risky browser extension, a website on the known-bad list, a cleared event log, BitLocker or Secure Boot switched off.

Automatic repair is a Pro feature. On Free, Invisibly detects and alerts as before.

## Offline and private by design

**In plain words:** nothing about you leaves your PC. There is nothing to sign up for and nothing to collect.

- **Fully offline.** Watching, repairing, and stopping ransomware or crypto-miners all happen on your PC with no internet connection needed.
- **One optional, one-way download.** Once a day Invisibly can fetch a signed list of newly found bad programs and websites. It sends nothing back — not even who you are — and you can turn it off in Advanced > Protections.
- **Never captured:** your name, email, phone, location, passwords, browsing history, documents or file contents. No device IDs, ad IDs, crash reports, usage statistics, analytics or tracking code.
- **Stays on your device.** Every check is read, judged and stored locally in `C:\ProgramData\Invisibly`. Delete that folder after uninstalling and nothing is left.

Full details: [Privacy Policy](privacy.html).

## Please read

Invisibly is built to help protect your PC from threats and to safeguard your privacy. It works quietly in the background, checks your settings for unwanted changes, and repairs or flags what it finds.

No security tool can promise to catch everything. Invisibly does its best, but it can miss a threat or occasionally flag something harmless. Please use your own judgment before you act on an alert, allow an item, or reset your baseline. If you aren't sure about something, check it before you trust it.

Invisibly supports your own good habits (updates, strong passwords, care with downloads and links). It doesn't replace them. It isn't a substitute for professional security advice or for backups of the files you can't afford to lose.

**Invisibly works completely offline: its checks and repairs need no internet connection, and no personal data is collected from our side.**

**No cloud. No telemetry. No AI. Everything runs locally.**

## What Invisibly is not

**In plain words:** it is not a replacement for your antivirus.

To be precise about scope: it's not an antivirus, an EDR (enterprise endpoint detection and response), a SIEM (a company-wide log system), a vulnerability scanner, or a network IDS (intrusion detection system) — it doesn't scan files or hunt on your network. It's a continuous endpoint *integrity* monitor: think of it as the smoke alarm for your computer's security settings, not a fire extinguisher for viruses. Use it alongside your antivirus, not instead of it.

## What Invisibly can not do (honest limits)

**In plain words:** Invisibly makes your PC harder to quietly take over and tells you fast when something changes. It can not make a PC unhackable, and it is only one layer next to Windows Security, updates, strong passwords with two-step login, and backups.

- **It reports changes.** Most checks compare against how your PC looked when Invisibly first saw it. If something was already weak at that moment, a check may not call it out. Where we found this to matter (for example BitLocker already switched off) it now shows a quiet warning, but not every check can.
- **It can not stop brand-new malware, and it can not stop a program running as you from reading your own files.** The optional theft guard places fake secret files and tells you if a program touches them, and it reminds you when real keys or passwords are lying around unprotected. It warns; it does not lock your files.
- **Website-name checks read Windows' recent lookups.** Very short-lived names, and made-up names that do not exist, can be missed.
- **Its own saved data is protected, not unbreakable.** The seal key is tied to your Windows account and its file can only be read by Invisibly's administrator-level program, which stops other accounts and ordinary programs running as you. Malware that you allow to run as administrator can still reach it.
- **Not yet independently audited.** Treat it as an extra pair of eyes, not a guarantee.

*Technical detail:* saved baselines and timeline entries use one AES-256-GCM layer plus an HMAC-SHA256 signature chain, keyed by a random master key wrapped with Windows DPAPI (user scope). There is no password-based layer.

## At a glance: what makes Invisibly different

| | Antivirus | Windows Firewall | Enterprise EDR | **Invisibly** |
|---|:---:|:---:|:---:|:---:|
| Scans files for known viruses | ✅ | ❌ | ✅ | ❌ *(by design — see "What Invisibly is not")* |
| Watches your security **settings** for tampering | ❌ | ❌ | ⚠️ needs IT setup | ✅ |
| Fixes things automatically when it's safe to | ❌ | ❌ | ⚠️ | ✅ |
| Works out of the box, no IT admin needed | ✅ | ✅ | ❌ | ✅ |
| Runs locally — no data leaves your PC (optional daily update check) | ❌ | ✅ | ❌ | ✅ |
| Typical memory use | 200–500 MB | <50 MB | 500 MB–2 GB | ~30 MB |

*This is the short version. For the full technical breakdown of all 56 monitored signals, see the detailed table below.*

## Full Technical Comparison (56 Signals)

*A "signal" is one thing Invisibly keeps an eye on. ✅ = does it, ❌ = doesn't, ⚠️ = partly or depends on the vendor.*

| Capability | Antivirus | Firewall | EDR | Invisibly |
|---|:---:|:---:|:---:|:---:|
| **Core Protection** | | | | |
| Malware Scanning | ✅ | ❌ | ✅ | ❌ *(not Invisibly's job by design)* |
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
| Defender Exclusion Monitoring + Automatic Removal | ❌ | ❌ | ⚠️ | ✅ |
| Security Setting Tamper Guard (Tamper Protection, SMBv1, sign-in secrets shield) | ❌ | ❌ | ⚠️ | ✅ |
| **Persistence Monitoring** | | | | |
| Startup Entry Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| New Startup Program Check (signature + location) | ⚠️ | ❌ | ⚠️ | ✅ |
| Scheduled Task Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Windows Services Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Hidden Start-up Hook Monitoring (Winlogon, debugger, AppInit) | ❌ | ❌ | ⚠️ | ✅ |
| **Account Monitoring** | | | | |
| New User Account Alert | ❌ | ❌ | ⚠️ | ✅ |
| New Administrator Alert | ❌ | ❌ | ⚠️ | ✅ |
| **Hardware Protection** | | | | |
| HID Device Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Bluetooth Device Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Fake Keyboard (BadUSB) Alert | ❌ | ❌ | ⚠️ | ✅ |
| Camera / Microphone Spy Alert | ❌ | ❌ | ⚠️ | ✅ |
| Unknown Network Adapter Detection | ❌ | ❌ | ⚠️ | ✅ |
| **Threat Detection** | | | | |
| Homoglyph Domain Detection | ❌ | ❌ | ❌ | ✅ |
| Unicode Bidi / Zero-width Attack Detection | ❌ | ❌ | ❌ | ✅ |
| Suspicious Process Detection | ⚠️ | ❌ | ⚠️ | ✅ |
| Real-Time Ransomware Detection + Pause | ⚠️ | ❌ | ⚠️ | ✅ |
| Remote-Access / Tunnel Tool Alert | ❌ | ❌ | ⚠️ | ✅ |

*⚠️ = Partial or vendor-dependent*

## Security Testing Results

**In plain words:** we ran Invisibly through independent security checkers to confirm it's safe. The few warnings are the checkers being cautious about any program that, like a security tool, changes system settings.

Invisibly has been tested through multiple independent security platforms to verify its safety and legitimacy.

| Test Platform | Result |
|---|---|
| VirusTotal (70 engines) | 65/70 clean — 5 false positives from behavioral/AI engines |
| CAPE Sandbox | 0/100 malicious score — all behaviors are by design |
| MITRE ATT&CK Mapping | 33 techniques observed — all expected for a security tool |
| Sigma Rules | 1 HIGH, 1 MEDIUM, 3 LOW — all false positives from expected PowerShell monitoring |

## What Invisibly Monitors

**In plain words:** Invisibly keeps an eye on everything an attacker is likely to touch first, grouped below by topic. Each group says what it covers and why it matters.

Invisibly watches the security settings that attackers target — 56 signals in total. Some bullets cover more than one check.

**Network (19 signals)**

*Your internet connection. Why it matters: change this and an attacker can send you to fake sites or listen in.*

- DNS configuration (the address book that turns website names into addresses)
- Hosts file (a local list that can quietly override that address book)
- Proxy settings (a middleman your traffic is sent through)
- ARP table (who is who on your local network — spoofing it lets someone impersonate your router)
- Network adapters
- WiFi SSID and network profile (public/private)
- VPN state
- New network devices
- DHCP configuration (the router's hand-out of addresses)
- DNS-over-HTTPS and IPv6 status
- DNS server or proxy matches a signed known-bad threat feed
- Wi-Fi safety (open or weak network, fake copy of a trusted network, changed router)
- Website names looked up: crypto-coin mining servers (on by default); free dynamic-DNS addresses, machine-generated looking names, and risky names such as .zip/.mov, throw-away names or one-letter-off copies of famous sites (off by default)

**Security Controls (15 signals)**

*Windows' own protections. Why it matters: these are the first things malware tries to switch off.*

- Windows Firewall
- Windows Defender, and its exclusions (a new folder, program or file type Defender is told to ignore — risky ones are removed automatically)
- User Account Control (UAC — the "do you allow this?" prompt), Windows Update, System Restore and SmartScreen
- Secure Boot and Credential Guard (protect the PC's startup and stored sign-ins)
- BitLocker *(requires a BitLocker-capable Windows edition and a TPM — see note below)*
- LAPS (a company-network feature — a change is simply noted quietly)
- Windows Event Log (the PC's activity diary; a stopped log is restarted automatically)
- Trusted root certificate authorities (a new one can enable silent HTTPS interception)
- Far out-of-date risky apps (browser, Zoom, PDF reader... - a gentle reminder to update)
- Security settings switched off later (Defender Tamper Protection, the Windows sign-in secrets shield, old SMBv1 file sharing, Office macro safety, Windows Script Host - put back automatically where that is safe)

**Persistence (6 signals)**

*Things that start by themselves. Why it matters: it's how a bad program keeps coming back after you restart.*

- Startup entries, with each new startup program checked by its digital signature (proof of who made it) and where it lives
- Scheduled tasks and Windows Services
- Hidden start-up hooks (a changed sign-in shell or Userinit, a debugger planted on another program, AppInit DLLs, start-up policy entries — the first three are put back automatically)
- Risky browser extensions and hijacked browser settings (Chrome, Edge, Brave: add-ons installed outside the official store, changed search engine, home page or proxy)

**Accounts (2 signals)**

*Who can sign in to your PC. Why it matters: a secret new account is a back door.*

- New user account on this PC (or the built-in Administrator account switched on)
- New member of the Administrators group

**Hardware (4 signals)**

*Devices plugged into your PC. Why it matters: some gadgets pretend to be something harmless.*

- Keyboard/mouse (HID) and Bluetooth devices
- Fake keyboards - a new keyboard-type device, such as a USB gadget that pretends to be a keyboard to type commands by itself ("BadUSB")
- Android emulators (BlueStacks, Nox, LDPlayer... - optional, off by default)

**Active Attacks (7 signals)**

*Signs that something bad is happening right now.*

- Brute force login attempts (someone guessing your password over and over) — automatically blocked at the firewall
- Remote Desktop (RDP) unexpectedly enabled — automatically disabled
- Suspicious processes (running from Temp/Downloads/Desktop)
- Unexpected new software installed (noted quietly, no pop-up)
- Remote-access / tunnel tools that weren't there before (AnyDesk, TeamViewer, ngrok... - the tech-support-scam step)
- Camera or microphone used by an unsigned program, or one running from Downloads/Temp (spyware)
- Data-thief trap: fake secret files (a fake key, a fake password list) that no honest program opens. If a program reads, changes or deletes one, you are told. It also reminds you when real keys or passwords are lying around unprotected (file names only, never contents). Optional, off by default, and switching it off removes the fake files

**Social Engineering (3 signals)**

*Tricks designed to fool you, not the computer.*

- Homoglyph domains (website names that swap in look-alike letters, like a Cyrillic "о" for an "o")
- Unicode bidi / zero-width character attacks (hidden characters disguising a redirect)
- Fake file extensions (e.g. `invoice.pdf.exe`)

> **Note on BitLocker:** BitLocker Drive Encryption isn't available on every Windows setup — it needs a BitLocker-capable edition (Pro/Enterprise/Education) or Windows Home Device encryption, and a TPM. Where Windows cannot report the status at all, that specific check has nothing to report and stays quiet rather than alerting on a status it can't determine. Where Windows reports that protection is off (for example a drive that is encrypted but has no key protector), Invisibly shows a quiet warning instead of saying "enabled". Every other signal is unaffected.

## Behavior-Based Detection

**In plain words:** Invisibly doesn't need to recognise a specific attack. If your security settings change in a way you didn't choose, it notices — even for attacks nobody has seen before.

Invisibly doesn't just check for known threats — it detects **any** change to your security configuration. This means Invisibly catches **unknown threats** too — not just pre-defined signatures.

*One exception to the 30-second check:* ransomware can finish encrypting a folder faster than that can catch it. See **Real-Time Ransomware Watch** below — it's the one thing in Invisibly that reacts instantly instead of on the next cycle.

## Integrity Score

**In plain words:** one number from 0 to 100 that says how healthy your PC's protection is right now. 100 means everything is as it should be.

Every system receives a score between 0 and 100 based on current state — not historical events.

*Example:*

- Firewall: Healthy
- Defender: Healthy
- DNS: Warning (-12 points)
- System Health: 88/100

## Security Timeline

**In plain words:** a diary of what happened and what Invisibly did about it. Nobody can quietly edit past entries.

Every event is recorded in an append-only, tamper-evident timeline.

*Example:*

- 14:02 — DNS changed → Restored
- 14:03 — Integrity Score: 100
- 14:05 — RDP enabled → Disabled automatically

## Baseline Protection

**In plain words:** the "baseline" is Invisibly's saved snapshot of how your settings should look. Everything is compared against it, so it has to be tamper-proof. It's locked with a digital seal, and sealed with a key that is tied to your Windows account.

The baseline is:

- Cryptographically signed (HMAC-SHA256 — a digital seal that breaks if anyone edits the file)
- Versioned, with rollback protection
- Tamper-detected
- Signing key protected at rest with Windows DPAPI, tied to your Windows account — not stored as a plain file
- Self-healing for infrastructure problems (a locked-down data folder, a stale signature from a benign cause); a genuinely tampered executable never self-heals — it's always surfaced to you instead

If the baseline is tampered with and the executable itself checks out clean, the daemon (the background program) regenerates it automatically. If the executable itself fails its own signature check, auto-repair disables and the daemon shows a clear alert (dashboard banner, tray icon, notification) rather than fixing anything silently.

## Ghost Mode (Public WiFi)

**In plain words:** on café or airport Wi-Fi, other people on the same network can try to reach your PC. Ghost Mode switches on automatically there to shut that door, and switches off when you're back on a network you trust.

Auto-enables on public networks, auto-disables when you're back on a trusted one. Deliberately inbound-only — it never touches outbound traffic, so it can't break your internet:

- Blocks risky inbound ports
- Blocks inbound ICMP (ping requests)
- Disables Network Discovery and file sharing

## Real-Time Ransomware Watch

**In plain words:** ransomware locks your files and demands money. This watches your most important folders live and, if a program starts scrambling files, freezes (pauses) that program before it does more damage. Nothing is deleted, and you decide what happens next.

Watches Documents, Desktop, Pictures, and Downloads live — not on the usual 30-second cycle. It reacts to either of two signs of mass encryption:

- A **guard file** (one hidden, harmless file Invisibly places in each watched folder) being changed, renamed or deleted — nothing legitimate does that
- A burst of 20+ file changes within 10 seconds

On either, it measures which program is writing the most data. If that program is **not validly signed** and not a Windows/Invisibly program — and either it touched a guard file, or the changed files also look encrypted — Invisibly **pauses** it (reversible, nothing is deleted) and shows a card on the dashboard plus a tray notice:

- **Stop it** ends the program. **It's fine - resume** continues it and remembers it, so it is never paused again. No answer = it stays paused.
- Signed programs (backup tools, sync clients, archivers) and Windows itself are never paused — they only raise the alert
- Instant alert (highest priority — above even a tamper alert); auto-clears once file activity settles down
- Pro feature. Offline: signature checks never touch the network
- Fixed to these four folders on purpose — not user-editable yet, and deliberately not extended to a whole drive (more folders means more background noise, and Windows can start silently dropping change notifications under heavy load)
- Guard files are hidden system files named `!0_invisibly_guard_do_not_edit.docx`. If you uninstall Invisibly they stay behind — safe to delete

## Hidden Crypto-Miner Pause

**In plain words:** crypto-miners secretly use your PC's power (and electricity) to make money for someone else, leaving it slow and hot. This spots and pauses one.

Every 15 seconds Invisibly checks CPU use. A program that is unsigned, runs from a user-writable folder (Temp, Downloads, AppData, ProgramData), has no visible window, and keeps the CPU heavily busy (35%+ of the whole processor) for 10 minutes straight is **paused**, with the same Stop it / It's fine - resume card. Signed apps, programs with a window, Windows and Invisibly itself are never touched. Pro feature.

## System Tray

**In plain words:** the small icon near your clock tells you the state at a glance.

| Color | Status |
|---|---|
| 🟢 Green | System maintained |
| 🟡 Yellow | Drift detected |
| 🔴 Red | Critical issues; a security alert (executable tamper check failed); or (highest priority) possible ransomware activity detected in real time |
| 🔵 Blue | Ghost Mode active |
| ⚪ Gray | Daemon offline, or running without admin rights (limited protection) |

## Performance

**In plain words:** it's light — you shouldn't notice it running.

| Metric | Value |
|---|---|
| RAM | ~30 MB |
| CPU (idle) | <1% |
| Disk | <20 MB |
| Network | Localhost only |

## Quick Start (MSIX)

1. **Download and install** — open the **Microsoft Store**, search for **Invisibly** and click Install. The Store handles installation, updates and (for Pro) the subscription.
2. **Launch** — open Invisibly from the Start menu. On first run it creates a Windows Scheduled Task so it can run with full privileges at every login, without a permission prompt each time; until that first elevated run, it operates in monitor-only mode (detects and alerts, doesn't auto-repair).
3. This starts the daemon and tray automatically at every login from then on — no manual launch needed.
4. **Optional — set Home WiFi**: supported via the daemon's local API (`POST /home`); not yet exposed as a dashboard button.

## Dashboard

**In plain words:** the control panel. You never have to open it — it's there if you want to look.

Right-click the tray icon, or open:

```
http://127.0.0.1:12790/dashboard
```

**Controls:**

- Enable/Disable Ghost Mode
- Run Auto-Repair
- Reset Baseline (accept how your PC is right now as the new "normal")
- Rollback Changes
- Verify Trust
- Restart Daemon
- Scan for Issues (read-only check of every signal; changes nothing)

## Free and Pro

| | Free | Pro (Microsoft Store subscription) |
|---|:---:|:---:|
| Detects changes to all 56 security signals | ✅ | ✅ |
| Alerts, integrity score, trust level, dashboard | ✅ | ✅ |
| Automatic repair of unsafe changes | ❌ | ✅ |
| Ghost Mode (public Wi-Fi lock-down) | ❌ | ✅ |
| Ransomware and hidden crypto-miner pause | ❌ | ✅ |

## Requirements

- Windows 10/11 (64-bit)
- Administrator privileges for auto-repair

## Keywords

endpoint integrity, configuration monitoring, behavior-based detection, DNS hijacking, ARP spoofing, hosts file protection, firewall monitoring, defender monitoring, UAC protection, Windows Update monitoring, System Restore protection, SmartScreen monitoring, Bluetooth security, HID protection, RDP protection, homoglyph detection, zero-width attacks, Unicode bidi attacks, brute force detection, proxy monitoring, root CA monitoring, scheduled tasks monitoring, startup persistence, Windows Services monitoring, Ghost Mode, public WiFi protection, stealth mode, integrity score, trust level, security baseline, auto-repair, self-healing, tamper detection, DPAPI encryption, ransomware detection, real-time file monitoring, configuration drift detection, offline security, no telemetry, privacy-first, lightweight, Windows security, Rust, autonomous endpoint protection, security timeline, Defender exclusions, Tamper Protection, SMBv1, LSASS protection, Office macros, Windows Script Host, hidden startup hooks, quiet security

## License

*Proprietary — All Rights Reserved*

© 2026 DeltaIQx LLP

> **Safety valve:** create an empty file `C:\ProgramData\Invisibly\guard_disabled.txt` and Invisibly will only alert — it will never pause a program — until the file is deleted. To free a program that is still paused (for example after uninstalling), end it in Task Manager or restart the PC.
