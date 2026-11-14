# Threat-feed source policy (decided 2026-11-04)

Applies before any signed feed is published (the feed still uses the demo key).

1. **Licence.** Do not bundle GPLv3 data (HaGeZi) in the paid, closed Store app. Use permissive lists: StevenBlack (MIT), Anudeep (MIT), hBlock (MIT), abuse.ch URLhaus / Feodo Tracker. Read each list's licence file before use and record it here. Add HaGeZi only with written permission or a confirmed licence that allows it.
2. **oisd.nl: excluded.** It is a large ad/tracker list, not security-only; it causes false alarms. Security-only lists (malware, phishing, command-and-control) only.
3. **Severity.** Looked-up bad names: 1-2 sites = Medium -6, 3+ = High -12 (integrity.rs evaluate_threat_dns). A configured bad DNS server or proxy stays Critical -20.
