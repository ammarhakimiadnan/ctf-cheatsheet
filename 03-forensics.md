# Forensics Cheatsheet

## 1. Live-Box Forensics (artifacts found during a boot2root)

**First move on any file:** identify it before anything else.
```bash
file <filename>
xxd <filename> | head          # check magic bytes vs extension
binwalk <filename>             # embedded files/firmware
binwalk -e <filename>          # extract embedded content
exiftool <filename>            # metadata (GPS, author, software, comments)
strings -n 8 <filename> | less  # readable text, look for flag{ or passwords
```

**Image steganography**
```bash
steghide info <file>
steghide extract -sf <file>              # try blank passphrase, then wordlist
zsteg <file>.png                         # LSB stego on PNG/BMP
stegsolve                                # GUI, bit-plane viewer
outguess -r <file> out.txt
pngcheck -v <file>                       # check for corrupted/appended chunks
```
- Check image dimensions vs displayed size (hidden data after IEND chunk)
- Try swapping/fixing corrupted headers

**Archive / file carving**
```bash
binwalk -e <file>
foremost -i <file> -o output/
photorec <file>
7z x <file>            # try with known/guessed password; john/hashcat to crack zip pw
zip2john <file> > hash.txt && john hash.txt
```

**Memory forensics (Volatility)**
```bash
volatility3 -f mem.dmp windows.info
volatility3 -f mem.dmp windows.pslist
volatility3 -f mem.dmp windows.pstree
volatility3 -f mem.dmp windows.cmdline
volatility3 -f mem.dmp windows.filescan | grep -i <keyword>
volatility3 -f mem.dmp windows.dumpfiles --virtaddr <addr>
volatility3 -f mem.dmp windows.malfind      # injected code
volatility3 -f mem.dmp windows.netscan      # network connections
```
For Linux memory dumps use the `linux.*` plugin equivalents (need matching profile/symbol table).

**Network forensics (pcap)**
```bash
wireshark capture.pcapng
# Filters: http.request | ftp or ftp-data | dns | tcp.stream eq 0
tshark -r capture.pcapng --export-objects http,output/   # pull out transferred files
networkminer capture.pcapng                                # auto-extracts files/creds
```
- Look for cleartext creds in FTP/HTTP/Telnet streams
- Filter `dns` for exfiltration via DNS tunneling
- Check for unusual ports, beaconing patterns, large outbound transfers

**Disk images**
```bash
mmls disk.img                  # partition table
fls -r -o <offset> disk.img    # list files
icat -o <offset> disk.img <inode> > out.file
autopsy                        # GUI, easiest for timeline + deleted file recovery
```

**Encoding / crypto quick checks**
```bash
echo '<string>' | base64 -d
echo '<string>' | xxd -r -p          # hex decode
# CyberChef -- magic wand for auto-detecting encoding chains
```
- Try ROT13, Base32/58/85, hex, binary, URL-encoding in sequence
- A long base64-looking blob inside a pcap/memdump/image is very often the flag, double/triple encoded

**General forensics checklist**
1. `file` + `exiftool` + `strings` on every artifact immediately
2. Check for appended data after the file's expected EOF marker
3. If password-protected, try: blank, `password`, challenge name, rockyou.txt
4. CyberChef for anything that looks encoded but you can't place
5. Timeline things (file/pcap timestamps, process start times) when a question asks "when"

## 2. Forensic Artifact Analysis (given files, not a live box)

Triage order:
1. `file`, `exiftool`, `md5sum`/`sha256sum` the artifact — confirm type and match any provided hash
2. Identify the right tool category (table below)
3. Work the question list given — answer what's asked, don't try to "solve" the whole artifact

| Artifact type | Primary tools | What to look for |
| --- | --- | --- |
| Disk image (.img/.E01/.vmdk) | Autopsy, FTK Imager, `mmls`/`fls`/`icat`, Registry Explorer | Deleted files, recent docs, browser history, registry run keys, recycle bin, $MFT timeline |
| Memory dump (.mem/.vmem/.dmp) | Volatility3, Volatility2 | Process list/tree, command lines, network connections, injected code, extracted files, registry hives in memory |
| Network capture (.pcap/.pcapng) | Wireshark, tshark, NetworkMiner, Zeek | Credentials, exfil, C2 beacon, DNS tunneling, extracted files/objects |
| Windows Event Logs (.evtx) | `evtx_dump`, Event Viewer, Chainsaw, DeepBlueCLI | 4624/4625 (logon), 4688 (process creation), 4720 (user created), 1102 (log cleared), 4103/4104 (PowerShell) |
| Browser artifacts | DB Browser for SQLite, `hindsight` | History/Downloads/Cookies DBs, cache, session storage |
| Email (.eml/.pst/.msg) | `readpst`, manual header inspection | Received/X-Originating-IP headers, SPF/DKIM, attachments, reply-to mismatches |
| Mobile (Android/iOS backup) | ALEAP, iLEAPP, `adb`, sqlite browser | SMS/call DBs, app data DBs, shared_prefs, WAL files (freshest data) |
| Office docs (.docx/.xlsx/.pptx) | `oletools` (`olevba`, `oleid`), unzip | VBA macros, embedded objects, `docProps/core.xml`, hidden sheets/slides |
| PDF | `pdf-parser`, `peepdf`, `qpdf` | JavaScript objects, embedded files, `/OpenAction`, revision history |
| Browser/JS challenges | Dev tools, `jsbeautifier`, deobfuscators | Obfuscated JS, localStorage/sessionStorage, hidden form fields, source maps |

**Timeline building**
```bash
log2timeline.py timeline.plaso <artifact-or-mount>
psort.py -o l2tcsv timeline.plaso -w timeline.csv
```
Correlate: file-system + event log + memory process + pcap timestamps.

**Windows registry quick hits**
- `NTUSER.DAT\...\RunMRU` / `\TypedPaths` — what the user typed/ran
- `SYSTEM\...\USBSTOR` — USB device history
- `SOFTWARE\...\Run` / `RunOnce` — persistence
- `SAM` — accounts (crack with `samdump2`/`secretsdump.py`)
- Shimcache / Amcache — evidence of execution even if deleted

**Volatility recipe for "what did the attacker do"**
```bash
volatility3 -f mem.dmp windows.pstree              # odd parent/child
volatility3 -f mem.dmp windows.cmdline              # exact commands run
volatility3 -f mem.dmp windows.netscan              # C2/exfil connections
volatility3 -f mem.dmp windows.malfind              # process hollowing / injected shellcode
volatility3 -f mem.dmp windows.hashdump             # local creds if SAM/SYSTEM resident
volatility3 -f mem.dmp windows.filescan | grep -i <ext or keyword>
volatility3 -f mem.dmp windows.dumpfiles --virtaddr <addr> -o out/
```

**Keep answers in the exact format asked** (MITRE ATT&CK ID, SHA256, exact timestamp with timezone, full file path).

## 3. Full Volatility Walkthrough (dumping + analyzing live memory)

**Step 1 — get a memory image off the box**
```bash
# Linux, if LiME is available/installable:
insmod lime.ko "path=/tmp/mem.lime format=lime"
# fallback, dump /proc/kcore (slow, big, no extra tools):
cp /proc/kcore /tmp/mem.raw
# Windows, with winpmem/DumpIt present or uploaded:
winpmem.exe mem.raw
```
Transfer it back with the file-transfer steps in the Tools & Setup tab.

**Step 2 — identify the profile/symbols**
```bash
volatility3 -f mem.raw windows.info      # confirms it can parse the image + OS build
```

**Step 3 — core triage, in this order**
```bash
volatility3 -f mem.raw windows.pstree       # odd parent/child (e.g. winword.exe -> cmd.exe)
volatility3 -f mem.raw windows.cmdline      # exact command lines of every process
volatility3 -f mem.raw windows.netscan      # active/past network connections
volatility3 -f mem.raw windows.malfind      # process hollowing / injected shellcode
volatility3 -f mem.raw windows.hashdump     # local account hashes, if SAM/SYSTEM resident
```

**Step 4 — pull files/artifacts referenced by what you found**
```bash
volatility3 -f mem.raw windows.filescan | grep -i <keyword>
volatility3 -f mem.raw windows.dumpfiles --virtaddr <addr> -o out/
volatility3 -f mem.raw windows.memmap --pid <pid>           # dump a specific process's memory
```

**Step 5 — registry / clipboard / extras**
```bash
volatility3 -f mem.raw windows.registry.hivelist
volatility3 -f mem.raw windows.registry.printkey --key "<path>"
volatility3 -f mem.raw windows.clipboard
```

**Linux memory images** — same plugin names under `linux.*` (`linux.pslist`, `linux.bash` for shell history in memory, `linux.malfind`), but need a matching ISF symbol table for the exact kernel build (volatility3 often fetches this automatically; otherwise generate with `dwarf2json` against the target's kernel debug symbols).

**Fast workflow during a live b2r engagement:** dump memory only if genuinely stuck on persistence/creds and a process looks suspicious (`pstree`/`cmdline` first) — it's a heavier side-path, not the default route to root on an easy/intermediate box.
