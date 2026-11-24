# References

External cheatsheets, notes, and tools worth keeping open during the CTF.

## Cheatsheets & notes repos

| Resource | What it's good for |
|---|---|
| [amirr0r — Boot2Root cheatsheet](https://github.com/amirr0r/notes/blob/master/Infosec/boot2root-cheatsheet.md) | Personal boot2root notes from HTB / Vulnhub / THM / OSCP: port-by-port service enumeration, nmap/masscan, hash cracking, reverse shells, MSFvenom, buffer overflow skeleton |
| [amirr0r — File transfer techniques](https://github.com/amirr0r/notes/blob/master/Infosec/Pentest/file-transfer.md) | Moving files to/from Linux and Windows targets |
| [HackTricks](https://book.hacktricks.xyz/) | Huge methodology wiki — per-service pentesting pages, Linux/Windows privesc |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Payloads and bypasses for web vulns (SQLi, LFI, SSTI, XXE, upload, etc.) |
| [Internal All The Things](https://swisskyrepo.github.io/InternalAllTheThings/) | AD / internal network attack cheatsheets |
| [Pentestmonkey — Reverse shell cheatsheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) | Classic one-liner reverse shells |
| [Ignitetechnologies — Privilege Escalation](https://github.com/Ignitetechnologies/Linux-Privilege-Escalation) | Linux privesc walkthroughs |

## Quick-lookup tools (online)

| Resource | What it's good for |
|---|---|
| [revshells.com](https://www.revshells.com/) | Reverse shell generator (bash, python, nc, PowerShell…) with listener commands |
| [GTFOBins](https://gtfobins.github.io/) | Abusing Linux binaries for sudo / SUID / capabilities privesc |
| [LOLBAS](https://lolbas-project.github.io/) | Windows living-off-the-land binaries |
| [CyberChef](https://gchq.github.io/CyberChef/) | Decode / encode / decrypt anything (base64, hex, XOR, gzip…) |
| [CrackStation](https://crackstation.net/) | Online hash lookup |
| [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) | Identify hash type → hashcat mode |
| [Exploit-DB](https://www.exploit-db.com/) | Public exploits (offline: `searchsploit`) |
| [explainshell](https://explainshell.com/) | Break down unfamiliar commands |

## Enumeration & privesc scripts

| Resource | What it's good for |
|---|---|
| [PEASS-ng (linPEAS / winPEAS)](https://github.com/peass-ng/PEASS-ng) | Automated privesc enumeration |
| [pspy](https://github.com/DominicBreuker/pspy) | Watch processes / cron jobs without root |
| [SecLists](https://github.com/danielmiessler/SecLists) | Wordlists for directories, usernames, passwords, fuzzing |
| [Nishang](https://github.com/samratashok/nishang) | PowerShell offensive scripts and reverse shells |

## Forensics

| Resource | What it's good for |
|---|---|
| [Volatility 3 docs](https://volatility3.readthedocs.io/) | Memory forensics plugin reference |
| [Volatility 3 repo](https://github.com/volatilityfoundation/volatility3) | Install + plugin list |
| [CTF forensics field guide (Trail of Bits)](https://trailofbits.github.io/ctf/forensics/) | File carving, stego, packet capture, memory dumps |
| [Wireshark display filter reference](https://www.wireshark.org/docs/dfref/) | Filter syntax for pcap analysis |
| [Aperi'Solve](https://www.aperisolve.com/) | One-shot image stego analysis (zsteg, steghide, exiftool, binwalk) |
