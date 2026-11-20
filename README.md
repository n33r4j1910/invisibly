# Invisibly

*Your computer can be compromised without a single virus.*

**Invisibly is a silent guard for your Windows PC. It notices when something quietly changes your security settings — hijacked internet (DNS), a switched-off firewall or Defender, fake security certificates, new startup programs — and puts things right automatically.**

- **Works offline.** Everything runs on your own computer. No account, no sign-in, no cloud. The only internet use is two things you can switch off: a once-a-day signed-list download and Safe Browsing (Quad9 DNS), both explained in *Offline and private by design* below.
- **Captures nothing about you.** No name, email, files, passwords or browsing history is read or sent. No telemetry, no tracking.
- **Nothing to manage.** You see one thing: *Protected*.

Antivirus catches known bad files. Invisibly catches the quiet changes that attacks leave behind — the ones your antivirus has nothing to scan for.

## What it does, in plain words

Your PC has settings that keep you safe: the firewall (the gate that blocks unwanted connections), Windows Defender (Windows' built-in antivirus), and the "address book" that decides which website you reach when you type a name (DNS). Attackers know the easiest way in is often not a virus — it's quietly switching one of these off or changing it. Windows usually shows only a small warning icon that is easy to miss, and your antivirus is busy looking at files, not at the rest of your settings.

Invisibly remembers how your settings *should* look, checks them about every 30 seconds, and when something changes that you didn't change, it puts it back. If a decision really needs a person, it tells you in one clear sentence.

Under the hood, it continuously verifies that your Windows security configuration remains trustworthy, detects unauthorized changes, and restores safe settings.

## Why Invisibly?

Antivirus looks for bad *files*. Invisibly looks for bad *changes*. Most successful attacks don't drop malware at all — they modify DNS, disable the firewall, add persistence (a way to start again after a reboot), or quietly weaken your defenses. Invisibly monitors these security controls and restores them when it's safe to do so.

**A real example:** a piece of malware doesn't need to install anything you'd notice — it just quietly disables your firewall and adds itself to Windows startup so it survives a reboot. Windows won't warn you about either change; your antivirus has nothing to scan, since no file it recognizes as malicious was ever dropped. Invisibly catches both changes within about 30 seconds and restores them automatically.

## How this helps you beyond what Windows already gives you

**In plain words:** Windows already has a firewall, Defender and other protections. Invisibly doesn't replace them — it makes sure nobody has quietly switched them off. Concretely:

- **Defender gets disabled — or told to ignore a folder** (by malware, a rogue app, or an accidental click) → Windows shows at most a small warning icon, easy to miss. *Why it matters: a switched-off or blinded antivirus is how malware gets a free pass.* Invisibly alerts you, can turn Defender back on, and removes a risky "ignore this folder" rule (a Defender exclusion) the moment it appears.
- **A protection gets quietly switched off** — Tamper Protection (which stops other programs from turning Defender off), the shield around your Windows sign-in secrets (LSASS protection), the old unsafe SMBv1 file-sharing method → Windows doesn't announce it. *Why it matters: these are the locks attackers pick before stealing passwords or spreading to other PCs.* Invisibly notices and, where it's safe, switches them back.
- **DNS or your hosts file gets silently redirected** — a common way to steal banking or email logins by pointing a real-looking address at a fake site → Windows does not check for this, and most antivirus products only guard the hosts file, not the rest. *Why it matters: you can type your bank's real address and still land on a copy.* Invisibly checks, continuously.
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

**In plain words:** Invisibly itself sends nothing about you. There is nothing to sign up for and nothing to collect. Two optional features use the internet and can be switched off; they are listed here.

- **Fully offline.** Watching, repairing, and stopping ransomware or crypto-miners all happen on your PC with no internet connection needed.
- **One optional, one-way download.** Once a day Invisibly can fetch a signed list of newly found bad programs and websites. It sends nothing back — not even who you are — and you can turn it off in Advanced > Protections.
- **Safe Browsing (Quad9 DNS), on by default where it cannot override anyone.** Your website lookups then go to Quad9 instead of your provider, so Quad9 sees those website names (and your internet address, as any DNS does). It is left off when you or your company set your own DNS. Switch it off any time in the dashboard.
- **Never captured:** your name, email, phone, location, passwords, browsing history, documents or file contents. No device IDs, ad IDs, crash reports, usage statistics, analytics or tracking code.
- **Stays on your device.** Every check is read, judged and stored locally in `C:\ProgramData\Invisibly`. Delete that folder after uninstalling and nothing is left.

Full details: [Privacy Policy](privacy.html).

## Please read

Invisibly is built to help protect your PC from threats and to safeguard your privacy. It works quietly in the background, checks your settings for unwanted changes, and repairs or flags what it finds.

No security tool can promise to catch everything. Invisibly does its best, but it can miss a threat or occasionally flag something harmless. Please use your own judgment before you act on an alert, allow an item, or reset your baseline. If you aren't sure about something, check it before you trust it.

Invisibly supports your own good habits (updates, strong passwords, care with downloads and links). It doesn't replace them. It isn't a substitute for professional security advice or for backups of the files you can't afford to lose.

**Invisibly works completely offline: its checks and repairs need no internet connection, and no personal data is collected from our side. The only internet use is the optional daily list download and Safe Browsing (Quad9 DNS), both described under Offline and private by design.**

**No cloud. No telemetry. No AI. Everything runs locally.**

## What Invisibly is not

**In plain words:** it is not a replacement for your antivirus.

To be precise about scope: it's not an antivirus, an EDR (enterprise endpoint detection and response), a SIEM (a company-wide log system), a vulnerability scanner, or a network IDS (intrusion detection system) — it doesn't scan files or hunt on your network. It's a continuous endpoint *integrity* monitor: think of it as the smoke alarm for your computer's security settings, not a fire extinguisher for viruses. Use it alongside your antivirus, not instead of it.

## What Invisibly can not do (honest limits)

**In plain words:** Invisibly makes your PC harder to quietly take over and tells you fast when something changes. It can not make a PC unhackable, and it is only one layer next to Windows Security, updates, strong passwords with two-step login, and backups.

- **It reports changes.** Most checks compare against how your PC looked when Invisibly first saw it. If something was already weak at that moment, a check may not call it out. Where we found this to matter (for example BitLocker already switched off) it now shows a quiet warning, but not every check can.
- **It can not stop brand-new malware, and it can not stop a program running as you from reading your own files.** The optional theft guard places fake secret files and tells you if a program touches them, and it reminds you when real keys or passwords are lying around unprotected. It warns; it does not lock your files.
- **Website-name checks read Windows' recent lookups.** Very short-lived names, and made-up names that do not exist, can be missed. A browser that uses its own secure DNS (DNS over HTTPS, switched on inside the browser) does not put its lookups in Windows' list, so Invisibly cannot see those sites.
- **It runs as a normal Windows program, not as a kernel driver.** It can watch Windows' list of known-dangerous drivers, put that setting back if it is switched off, and warn about a driver loaded from a user folder. It cannot stop a driver from loading, and it cannot defend against malware that already runs with kernel-level power.
- **The fake "I am not a robot" check reads history, after the fact.** It sees a pasted command in the Windows Run box once the command has been run, and only warns. It does not read what you type anywhere else.
- **Its own saved data is protected, not unbreakable.** The seal key is tied to your Windows account and its file can only be read by Invisibly's administrator-level program, which stops other accounts and ordinary programs running as you. Malware that you allow to run as administrator can still reach it.
- **Not yet independently audited.** Treat it as an extra pair of eyes, not a guarantee.

*Technical detail:* saved baselines and timeline entries use one AES-256-GCM layer plus an HMAC-SHA256 signature chain, keyed by a random master key wrapped with Windows DPAPI (user scope). There is no password-based layer.

## At a glance: what makes Invisibly different

**The biggest difference: Invisibly works fully offline.** Its checks and repairs need no internet, no account and no cloud. Antivirus and EDR products rely on cloud lookups and online management consoles to do their best work. (Invisibly's only internet use is two optional things you can switch off: a once-a-day signed-list download and Safe Browsing.)

| | Antivirus | Windows Firewall | Enterprise EDR | **Invisibly** |
|---|:---:|:---:|:---:|:---:|
| Works fully offline, no account, no cloud | ⚠️ scans yes, best protection needs cloud | ✅ | ❌ cloud-managed | ✅ |
| Scans files for known viruses | ✅ | ❌ | ✅ | ❌ *(by design, see "What Invisibly is not")* |
| Stops unknown malware as it runs | ✅ | ❌ | ✅ | ❌ *(only ransomware, miners, fork bombs, data thieves)* |
| Blocks network connections by rule | ⚠️ suites only | ✅ | ⚠️ | ⚠️ *(brute-force blocks, Ghost Mode)* |
| Watches your security **settings** for tampering | ⚠️ its own settings and Windows' main switches | ❌ | ✅ with setup | ✅ |
| Fixes settings back automatically | ⚠️ re-enables itself | ❌ | ✅ with setup | ✅ *(Pro; Free alerts only)* |
| Works out of the box, no IT admin needed | ✅ | ✅ | ❌ | ✅ |
| Central management for many PCs | ⚠️ business editions | ⚠️ via Group Policy | ✅ | ❌ |
| Independently audited / certified | ✅ | ✅ | ✅ | ❌ not yet |
| Typical memory use | 200–500 MB | <50 MB | 500 MB–2 GB | ~30 MB |

*This is the short version. For the full technical breakdown of all 58 monitored signals, see the detailed table below.*

## Full Technical Comparison (58 Signals)

*A "signal" is one thing Invisibly keeps an eye on. ✅ = does it as a normal part of the product, ❌ = doesn't, ⚠️ = partly, only some products, or only with extra setup. "EDR" means products such as Microsoft Defender for Endpoint or CrowdStrike. A real EDR sees far more than Invisibly (every process, file and network event); this table only compares the things Invisibly watches, and the first block shows where the others are stronger.*

| Capability | Antivirus | Firewall | EDR | Invisibly |
|---|:---:|:---:|:---:|:---:|
| **Where the others are stronger** | | | | |
| Malware Scanning | ✅ | ❌ | ✅ | ❌ *(not Invisibly's job by design)* |
| Virus Signature Updates | ✅ | ❌ | ✅ | ❌ |
| File Quarantine | ✅ | ❌ | ✅ | ❌ |
| Stops Unknown Malware as It Runs (kernel-level) | ✅ | ❌ | ✅ | ❌ *(runs as a normal program, not a driver)* |
| Blocks Network Traffic by Rule | ⚠️ | ✅ | ⚠️ | ⚠️ |
| Central Management of Many PCs | ⚠️ | ⚠️ | ✅ | ❌ |
| **Offline and Privacy** | | | | |
| Full Protection With No Internet | ⚠️ | ✅ | ❌ | ✅ |
| No Account, No Cloud, No Telemetry | ⚠️ | ✅ | ❌ | ✅ |
| **Configuration Integrity** | | | | |
| Endpoint Integrity Monitoring (saved baseline) | ❌ | ❌ | ⚠️ | ✅ |
| Integrity Score | ❌ | ❌ | ⚠️ | ✅ |
| Automatic Security Repair | ⚠️ | ❌ | ⚠️ | ✅ *(Pro)* |
| Configuration Drift Detection | ⚠️ | ❌ | ⚠️ | ✅ |
| Tamper-evident Event Timeline | ⚠️ | ⚠️ | ✅ | ✅ |
| **Network Protection** | | | | |
| DNS Monitoring | ⚠️ | ❌ | ✅ | ✅ |
| Hosts File Monitoring | ⚠️ | ❌ | ⚠️ | ✅ |
| Proxy Monitoring | ⚠️ | ❌ | ⚠️ | ✅ |
| ARP Spoofing Detection | ⚠️ | ❌ | ⚠️ | ✅ |
| New Network Device Detection | ⚠️ | ❌ | ✅ | ✅ |
| Brute-force Detection | ⚠️ | ⚠️ | ✅ | ✅ |
| DNS-over-HTTPS and IPv6 Status Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| DHCP Configuration Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| VPN State Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Wi-Fi Safety (open or weak network, fake copy of a trusted network, changed router) | ⚠️ | ⚠️ | ⚠️ | ✅ |
| Known-Bad Site / DNS / Proxy Match (signed threat list) + Known-Bad Site Stop (Pro) | ✅ | ❌ | ✅ | ✅ |
| Safe Browsing (filtering DNS, on by default where it cannot override you) | ✅ | ❌ | ⚠️ | ✅ |
| Crypto-Mining Server Lookup Alert | ⚠️ | ❌ | ✅ | ✅ |
| Data Smuggling Through DNS (tunnelling) Detection | ❌ | ❌ | ✅ | ✅ |
| Risky Website-Name Alerts (dynamic-DNS, machine-generated, look-alike, .zip/.mov) | ⚠️ | ❌ | ⚠️ | ✅ |
| **Windows Security Controls** | | | | |
| Windows Firewall Monitoring | ⚠️ | ❌ | ✅ | ✅ |
| Windows Defender Monitoring | ⚠️ | ❌ | ✅ | ✅ |
| UAC Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Windows Update Monitoring | ⚠️ | ❌ | ✅ | ✅ |
| System Restore Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| SmartScreen Monitoring | ⚠️ | ❌ | ⚠️ | ✅ |
| Secure Boot Monitoring | ❌ | ❌ | ✅ | ✅ |
| LAPS Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Defender Exclusion Monitoring + Automatic Removal | ⚠️ | ❌ | ✅ | ✅ |
| Security Setting Tamper Guard (Tamper Protection, SMBv1, sign-in secrets shield) | ⚠️ | ❌ | ⚠️ | ✅ |
| BitLocker Monitoring | ❌ | ❌ | ✅ | ✅ |
| Credential Guard Monitoring | ❌ | ❌ | ✅ | ✅ |
| Windows Event Log Monitoring + Automatic Restart | ❌ | ❌ | ⚠️ | ✅ |
| Trusted Root Certificate Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Out-of-date Risky App and Windows Patch-Age Reminder | ⚠️ | ❌ | ✅ | ✅ |
| Unexpected New Software Notice | ⚠️ | ❌ | ✅ | ✅ |
| **Persistence Monitoring** | | | | |
| Startup Entry Monitoring | ⚠️ | ❌ | ✅ | ✅ |
| New Startup Program Check (signature + location) | ⚠️ | ❌ | ✅ | ✅ |
| Scheduled Task Monitoring | ⚠️ | ❌ | ✅ | ✅ |
| Windows Services Monitoring | ⚠️ | ❌ | ✅ | ✅ |
| Hidden Start-up Hook Monitoring (Winlogon, debugger, AppInit) | ⚠️ | ❌ | ✅ | ✅ |
| **Account Monitoring** | | | | |
| New User Account Alert | ❌ | ❌ | ✅ | ✅ |
| New Administrator Alert | ❌ | ❌ | ✅ | ✅ |
| **Hardware Protection** | | | | |
| HID Device Monitoring | ⚠️ | ❌ | ⚠️ | ✅ |
| Bluetooth Device Monitoring | ❌ | ❌ | ⚠️ | ✅ |
| Fake Keyboard (BadUSB) Alert | ⚠️ | ❌ | ⚠️ | ✅ |
| Camera / Microphone Spy Alert | ⚠️ | ❌ | ⚠️ | ✅ |
| Unknown Network Adapter Detection | ❌ | ❌ | ⚠️ | ✅ |
| **Threat Detection** | | | | |
| Homoglyph Domain Detection | ⚠️ | ❌ | ⚠️ | ✅ |
| Unicode Bidi / Zero-width Attack Detection | ❌ | ❌ | ⚠️ | ✅ |
| Suspicious Process Detection | ✅ | ❌ | ✅ | ⚠️ *(Temp/Downloads/Desktop only)* |
| Real-Time Ransomware Detection + Pause | ✅ | ❌ | ✅ | ✅ |
| Remote-Access / Tunnel Tool Alert | ⚠️ | ❌ | ✅ | ✅ |
| Remote Desktop (RDP) Enabled Detection + Automatic Disable | ❌ | ⚠️ | ✅ | ✅ |
| Fake File Extension Detection (invoice.pdf.exe) | ✅ | ❌ | ✅ | ✅ |
| Fake "I am not a robot" (ClickFix) Detection | ⚠️ | ❌ | ⚠️ | ⚠️ *(after the fact, warns only)* |
| Hidden Crypto-Miner Detection + Pause | ✅ | ❌ | ✅ | ✅ |
| Runaway-Program (fork bomb) Stop | ❌ | ❌ | ⚠️ | ✅ |
| Browser Extension and Settings Hijack Monitoring | ⚠️ | ❌ | ⚠️ | ✅ |
| Android Emulator Alert | ❌ | ❌ | ⚠️ | ✅ |
| Ghost Mode (public Wi-Fi lock-down) | ⚠️ | ⚠️ | ❌ | ✅ |
| **Data-Theft Protection** | | | | |
| Decoy Secret Files (fake key, fake password list) Alert | ❌ | ❌ | ⚠️ | ✅ |
| Secret-Thief Stop (program sweeping the decoys) | ❌ | ❌ | ⚠️ | ✅ |
| Browser Cookie / Saved-Login Theft Watch | ⚠️ | ❌ | ✅ | ✅ |
| Wallet, Chat-app, Password-manager and Key-folder Watch | ⚠️ | ❌ | ⚠️ | ✅ |
| Unprotected Key / Credential File Reminder | ❌ | ❌ | ⚠️ | ✅ |

*⚠️ = partial, vendor-dependent or needs extra setup. Competitor ratings are general: they vary by product and edition.*

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

Invisibly watches the security settings that attackers target — 58 signals in total. Some bullets cover more than one check.

**Network (20 signals)**

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
- Data smuggling through DNS: many long, random-looking lookups under one website (on by default, can be switched off; remembers the last 15 minutes of lookups so a quick burst is not missed)

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
- Security settings switched off later (Defender Tamper Protection, the Windows sign-in secrets shield, old SMBv1 file sharing, Office macro safety, Windows Script Host, Windows' list of known-dangerous drivers, the Windows sign-in (NTLM) strength, the web-folder (WebDAV) client that sign-in leak attacks use - put back automatically where that is safe)

**Persistence (6 signals)**

*Things that start by themselves. Why it matters: it's how a bad program keeps coming back after you restart.*

- Startup entries, with each new startup program checked by its digital signature (proof of who made it) and where it lives
- Scheduled tasks and Windows Services
- Hidden start-up hooks (a changed sign-in shell or Userinit, a debugger planted on another program, AppInit DLLs, start-up policy entries, a driver loaded from a user folder such as Downloads or Temp, which is how attackers switch security tools off — the first three are put back automatically, a suspicious driver only raises an alert)
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
- Data-thief trap: fake secret files (a fake key, a fake password list) that no honest program opens. If a program reads, changes or deletes one, you are told. With key-folder protection on, you are also told when an unknown program tries to open your browser's saved logins and cookies, your chat-app and crypto-wallet folders, your password-manager folders or your key folders (the way data thieves take over accounts); each folder's own program (Firefox for Firefox, Discord for Discord) is never flagged. Pro also ends a program that opens 3 or more different fake files, which only a thief sweeping the PC does (see Secret-Thief Stop below). It also reminds you when real keys or passwords are lying around unprotected (file names only, never contents). On by default, can be switched off, and switching it off removes the fake files

**Social Engineering (4 signals)**

*Tricks designed to fool you, not the computer.*

- Homoglyph domains (website names that swap in look-alike letters, like a Cyrillic "о" for an "o")
- Unicode bidi / zero-width character attacks (hidden characters disguising a redirect)
- Fake file extensions (e.g. `invoice.pdf.exe`)
- Fake "I am not a robot" tricks (ClickFix): reads the Windows Run-box history and warns if a pasted download-and-run command was run. It never stores the command, and only alerts, because you may have typed it on purpose

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

## Safe Browsing (known-bad websites fail to load)

**In plain words:** Invisibly can point your PC at Quad9, a free, privacy-minded address book (DNS) that refuses to give out the address of websites known to spread malware or steal logins. A bad site then simply does not load.

It is **on by default**, but only where it cannot override anyone: when your PC takes its DNS from your router or internet provider, and is not joined to a company network. A DNS you typed in yourself, or a company one, is left alone. After switching, if the internet stops working, the old setting is put back automatically. Switch it off any time in the dashboard; it is never switched back on once you decide. *Honest limits:* Quad9 sees the website names you look up (it says it does not keep your IP address); browsers that use their own secure-DNS setting skip it; a brand-new bad site that is not on any list yet is not stopped.

## Known-Bad Site Stop

**In plain words:** the fast bad-site check (every 2 seconds) already tells you when your PC looks up a site on the signed bad-sites list. In Pro, Invisibly now also makes Windows refuse to look that **one exact name** up again for 24 hours, so it cannot load. After 24 hours the block removes itself.

Only that single name is affected, never a whole shared host that thousands of good sites use, and never Microsoft, Windows Update, GitHub or Invisibly's own list. Free tells you and leaves the blocking to you. A switch in Advanced > Protections turns it off and lifts every block at once; `C:\ProgramData\Invisibly\guard_disabled.txt` also makes every guard alert-only. *Honest limits:* it needs administrator approval; a browser with its own secure-DNS setting never asks Windows and is neither seen nor stopped; a page that is already open keeps working until you close it; the block is by name, so a bad site reached by its raw address is not stopped.

## Keeping Itself Up to Date (without new code)

**In plain words:** once a day Invisibly can fetch one signed file. It holds new bad programs and websites, and now also a short list of tuning rules. It never downloads or runs code, and it never sends anything about you.

- **The signed list** (bad programs, websites, remote-access tools, out-of-date apps) is checked against a built-in public key. A file with a wrong signature, or an older one than you already have, is ignored.
- **The rules** are only names and numbers: extra programs and sites that must never be touched, extra well-known developer tools, and stricter limits for the runaway-program and secret-thief stops. A rule can only make Invisibly **more** careful: the built-in numbers are the lowest allowed, so a rule can never make a guard trigger more easily.
- It learns your PC locally too: the saved baseline accepts what you accept, and the **Allow** button teaches it about one item you own. Nothing from your PC is ever sent back to improve it.

## Everyday Helpers

- **This week:** a plain-English summary of the last 7 days (what was found, what was fixed), worked out on your PC from the timeline.
- **Needs your attention:** a short list of the alert-only findings worth a look (a new user account, a new remote-access tool...), each in one plain sentence.
- **Allow ("This is mine"):** for the few alerts that can be your own doing (such as a browser add-on you built), accept that single item instead of resetting everything. Deliberately **not** offered for anything a thief could use to hide: new keyboards, remote tools, startup entries, accounts, the secret-theft guard.
- **Safe repairs:** before a repair that can change how the network behaves (DNS, hosts, proxy, firewall), Invisibly saves the old setting and tests the connection. If the internet worked before and stopped after the repair, the old setting is put back.
- **No repair loops:** a repair that keeps failing waits 2, 4, 8 minutes... (up to 6 hours) before trying again, so it never hammers your PC or fills the timeline.
- **Stopped-unexpectedly notice:** if Invisibly stopped in a way that is not a reboot, a log-off or an update (for example something ended it on purpose), it tells you the next time it starts.
- **Locked dashboard:** every request except the page itself needs a code that changes every 30 seconds, so another program on your PC cannot press the buttons.

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

## Secret-Thief Stop

**In plain words:** a data thief sweeps a PC for anything that looks like a key, a password list or a wallet. Invisibly leaves 5 fake ones that no honest program opens. A person may open one by mistake, so one touch is only an alert. A program that opens **3 or more different** fake files in a short time is sweeping.

When that program runs from a folder any user can write to (Downloads, Temp, AppData), in Pro Invisibly freezes it, ends it and records it in the timeline. Without Pro it records and tells you. It never touches Windows, Program Files, Invisibly or Defender, and it only ends the program whose full file path matches the event, never another program with the same name. A switch in Advanced > Protections turns it off, and `C:\ProgramData\Invisibly\guard_disabled.txt` makes every process guard alert-only.

*Honest limits:* it only stops a thief that is still running when the next scan reads the event (about 30 seconds). A smash-and-grab that already uploaded and exited is only reported. It ends that one program, not other programs it started. The watch on real secret folders (browser, wallets, key folders) relies on Windows' Controlled Folder Access reporting the access; Windows may not report every read, so this is an extra alarm, not a lock.

## Runaway-Program Stop

**In plain words:** a "fork bomb" is a program that keeps starting copies of itself, each copy starting more, until Windows runs out of room and the whole PC freezes. This stops one before that happens.

Every 2 seconds Invisibly looks at the list of running programs. It acts only when at least 150 new copies of the same program started within 15 seconds **and** they started each other in a chain at least 4 generations deep. A browser opening many tabs or a build tool starting helpers does not match: those start from one parent, a chain only 2 generations deep. Only the copies in that chain are touched; anything that was already running is not. Core Windows programs (sign-in, services, Explorer and similar) and Invisibly itself are never touched.

In Pro, Invisibly first freezes the whole chain so it cannot start more copies, catches the copies started in the meantime, then ends them, and records it in the timeline. Without Pro it only records and tells you. A switch in Advanced > Protections turns it off, and creating the file `C:\ProgramData\Invisibly\guard_disabled.txt` makes every process guard alert-only.

*Honest limit:* it runs in user mode. A bomb that freezes the PC faster than a 2-second look, or one that runs with kernel-level power, can still win. It ends nothing outside the detected chain.

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
- Allow (accept one alert that is yours)
- Pause Invisibly for 1 hour (it always switches itself back on)
- Safe Browsing switch (Quad9 DNS)
- Advanced > Protections: a switch for each optional protection
- This week, and Needs your attention
- Copy or save a plain-text report (the "This week" card, or the full report)
- See which folders the ransomware watch is guarding
- A quiet notice when a newer version of Invisibly is available
- Verify Trust
- Restart Daemon
- Scan for Issues (read-only check of every signal; changes nothing)

## Free and Pro

| | Free | Pro (Microsoft Store subscription) |
|---|:---:|:---:|
| Detects changes to all 58 security signals | ✅ | ✅ |
| Alerts, integrity score, trust level, dashboard | ✅ | ✅ |
| Automatic repair of unsafe changes | ❌ | ✅ |
| Ghost Mode (public Wi-Fi lock-down) | ❌ | ✅ |
| Ransomware and hidden crypto-miner pause | ❌ | ✅ |
| Runaway-program stop (fork bombs) | ❌ | ✅ |
| Secret-thief stop (program sweeping the fake secret files) | ❌ | ✅ |
| Known-bad site stop (24-hour name block) | ❌ | ✅ |
| Safe Browsing (Quad9 DNS) and the signed list updates | ✅ | ✅ |

## Requirements

- Windows 10/11 (64-bit)
- Administrator privileges for auto-repair

## Keywords

endpoint integrity, configuration monitoring, behavior-based detection, DNS hijacking, ARP spoofing, hosts file protection, firewall monitoring, defender monitoring, UAC protection, Windows Update monitoring, System Restore protection, SmartScreen monitoring, Bluetooth security, HID protection, RDP protection, homoglyph detection, zero-width attacks, Unicode bidi attacks, brute force detection, proxy monitoring, root CA monitoring, scheduled tasks monitoring, startup persistence, Windows Services monitoring, Ghost Mode, public WiFi protection, stealth mode, integrity score, trust level, security baseline, auto-repair, self-healing, tamper detection, DPAPI encryption, ransomware detection, real-time file monitoring, configuration drift detection, offline security, no telemetry, privacy-first, lightweight, Windows security, Rust, autonomous endpoint protection, security timeline, Defender exclusions, Tamper Protection, SMBv1, LSASS protection, Office macros, Windows Script Host, hidden startup hooks, quiet security

## License

*Proprietary — All Rights Reserved*

© 2026 DeltaIQx LLP

> **Safety valve:** create an empty file `C:\ProgramData\Invisibly\guard_disabled.txt` and Invisibly will only alert — it will never pause a program — until the file is deleted. To free a program that is still paused (for example after uninstalling), end it in Task Manager or restart the PC.
