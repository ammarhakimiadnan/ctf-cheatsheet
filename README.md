# CTF Cheatsheet

Reference notes for a boot2root + forensics CTF competition (4-5 boxes via OVPN, 2 forensics challenges).

- [`01-tools-setup.md`](01-tools-setup.md) — VPN connect, workflow, installing GitHub tools on the Pwnbox, configuring Burp Suite
- [`02-boot2root.md`](02-boot2root.md) — recon, service exploitation, web exploitation, privesc, shells/transfers, scenario patterns, step-by-step enumeration playbook, extra services, master OS-agnostic walkthrough, generic exploitation checklist templates
- [`03-forensics.md`](03-forensics.md) — forensic toolkit setup, artifact triage, full per-incident DFIR walkthroughs (memory, disk, pcap, event logs, Linux server, maldocs), Volatility deep-dive, answer-format discipline
- [`04-references.md`](04-references.md) — external cheatsheets, notes repos, online tools, and forensics references
- [`05-cve-poc-forensics.md`](05-cve-poc-forensics.md) — recognizing CVEs in forensic evidence, payload signatures, and instant PoC lookup for any CVE (2010→now)

To pull a copy directly onto the Pwnbox:
```bash
curl -O https://raw.githubusercontent.com/ammarhakimiadnan/ctf-cheatsheet/main/02-boot2root.md
```
